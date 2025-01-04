package application

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/ui"
	"github.com/NHAS/gohunt/config"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/crypto/bcrypt"

	"github.com/NHAS/session"
	"github.com/google/uuid"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type SessionEntry struct {
	UUID uuid.UUID
}

type Application struct {
	config config.Config

	store *session.SessionStore[SessionEntry]
	db    *gorm.DB

	provider rp.RelyingParty
}

func New(c config.Config) (*Application, error) {

	var newApplication = Application{
		config: c,
	}

	var err error
	newApplication.store, err = session.NewStore[SessionEntry]("session", "X-CSRF-Token", 8*time.Hour, 86400, false)
	if err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", c.Database.Host, c.Database.Port, c.Database.User, c.Database.Password, c.Database.DBname, c.Database.SSLmode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %s", err)
	}
	db.AutoMigrate(&models.User{}, &models.Injection{}, &models.InjectionRequest{}, &models.CollectedPage{})

	newApplication.db = db

	if os.Getenv("GOHUNT_USERNAME") != "" {

		var count int64
		if err := db.Model(&models.User{}).Count(&count).Error; err != nil {
			log.Println("failed to count users", err)
			return nil, fmt.Errorf("failed to count users: %s", err)
		}

		//  No users, time to make at least one admin
		if count == 0 {
			log.Println("No users exist, creating new admin")
			firstUserName := os.Getenv("GOHUNT_USERNAME")

			potentialPassword := os.Getenv("GOHUNT_PASSWORD")
			if potentialPassword == "" {
				potentialPassword = newApplication.generateRandom(16)
				log.Println("GOHUNT_PASSWORD: ", potentialPassword)
			}

			// Create new user
			user := models.User{
				UserDTO: models.UserDTO{
					Username: firstUserName,
					Email:    firstUserName + "@" + firstUserName,
					Domain:   firstUserName,
					IsAdmin:  true,
				},
			}

			b, err := bcrypt.GenerateFromPassword([]byte(potentialPassword), 10)
			if err != nil {
				return nil, fmt.Errorf("failed to generate password hash: %s", err)
			}

			user.Password = string(b)

			if err := db.Create(&user).Error; err != nil {
				return nil, fmt.Errorf("failed to save first user in database: %s", err)
			}
		} else {
			log.Println("Users exist, continuing start")
		}

	}

	if c.Features.Oidc.Enabled {

		hashkey := make([]byte, 32)
		_, err := rand.Read(hashkey)
		if err != nil {
			return nil, err
		}

		key := make([]byte, 32)
		_, err = rand.Read(key)
		if err != nil {
			return nil, err
		}

		cookieHandler := httphelper.NewCookieHandler([]byte(hashkey), []byte(key), httphelper.WithUnsecure())

		options := []rp.Option{
			rp.WithCookieHandler(cookieHandler),
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(10 * time.Second)),
		}

		chosenDomain := c.Domain
		if c.Features.Oidc.PublicURL != "" {
			log.Println("Using public_url for SSO redirect url")
			chosenDomain = c.Features.Oidc.PublicURL
		}

		u, err := url.Parse(chosenDomain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse domain: %s", chosenDomain)
		}

		if u.Scheme == "" {
			u.Scheme = "https"
		}

		u.Path = path.Join(u.Path, "/api/login/oidc/authorise")
		log.Println("OIDC callback: ", u.String())
		log.Println("Connecting to OIDC provider: ", c.Features.Oidc.IssuerURL)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		newApplication.provider, err = rp.NewRelyingPartyOIDC(ctx, c.Features.Oidc.IssuerURL, c.Features.Oidc.ClientID, c.Features.Oidc.ClientSecret, u.String(), []string{"openid"}, options...)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SSO Idp provider: %s, client_id %q, issuer_url %q, redirect_url %q", err, c.Features.Oidc.ClientID, c.Features.Oidc.IssuerURL, u.String())
		}
	}

	return &newApplication, nil
}

func (a *Application) Run() error {

	r := mux.NewRouter()

	// Can be used by caddy to determine if a certificate should be issued (see tls_ondemand ask/permission)
	r.HandleFunc("/check_domain", a.allowedDomain)

	// Backwards compatiablity with xss hunter tools
	injectionRequest := r.Host("api." + a.config.Domain).Subrouter()
	injectionRequest.PathPrefix("/api/record_injection").HandlerFunc(a.injectionRequestHandler).Methods("POST")

	collectionDomains := r.Host("{subdomain:.*}." + a.config.Domain).Subrouter()

	// Handles both post and options
	collectionDomains.HandleFunc("/js_callback", a.callbackHandler)
	collectionDomains.HandleFunc("/page_callback", a.collectPageHandler)

	// Public js collection routes
	collectionDomains.PathPrefix("/").HandlerFunc(a.probe)

	managementDomain := r.Host(a.config.Domain).Subrouter()

	// UI Routes
	managementDomain.HandleFunc("/", a.homepage).Methods("GET")
	managementDomain.HandleFunc("/app", a.app).Methods("GET")
	managementDomain.HandleFunc("/features", a.features).Methods("GET")
	managementDomain.PathPrefix("/static/").HandlerFunc(ui.Static).Methods("GET")

	// Public API routes
	managementDomain.HandleFunc("/api/login", a.loginHandler).Methods("POST")
	if a.config.Features.Oidc.Enabled {
		managementDomain.HandleFunc("/api/login/oidc", a.oidcLoginRedirect).Methods("GET")
		managementDomain.HandleFunc("/api/login/oidc/authorise", a.oidcLoginHandler).Methods("GET")
	}

	managementDomain.PathPrefix("/api/record_injection").HandlerFunc(a.injectionRequestHandler).Methods("POST")

	// Optional features
	if a.config.Features.Signup.Enabled {
		managementDomain.HandleFunc("/signup", a.signup).Methods("GET")
		managementDomain.HandleFunc("/api/register", a.registerHandler).Methods("POST")
	}

	// Health check
	managementDomain.HandleFunc("/health", a.healthHandler).Methods("GET")

	// Authorisation required API routes
	authorizedPages := http.NewServeMux()
	authorizedPages.HandleFunc("GET /collected_pages", a.getCollectedPagesHandler)
	authorizedPages.HandleFunc("DELETE /delete_injection", a.deleteInjectionHandler)
	authorizedPages.HandleFunc("DELETE /bulk_delete_injection", a.deleteBulkInjections)
	authorizedPages.HandleFunc("DELETE /delete_collected_page", a.deleteCollectedPageHandler)
	authorizedPages.HandleFunc("GET /user", a.userInformationHandler)
	authorizedPages.HandleFunc("PUT /user", a.editUserInformationHandler)
	authorizedPages.HandleFunc("GET /payloadfires", a.getXSSPayloadFiresHandler)
	authorizedPages.HandleFunc("POST /resend_injection_email", a.resendInjectionEmailHandler)
	authorizedPages.HandleFunc("GET /logout", a.logoutHandler)
	// Admin pages

	adminPages := http.NewServeMux()
	adminPages.HandleFunc("GET /users", a.adminGetAllUsers)
	adminPages.HandleFunc("PUT /users", a.adminEditUser)

	adminPages.HandleFunc("DELETE /users", a.adminDeleteUser)
	adminPages.HandleFunc("DELETE /users/data", a.adminDeleteUserData)

	authorizedPages.Handle("/admin/", http.StripPrefix("/admin", a.isAdmin(adminPages)))

	managementDomain.PathPrefix("/api/").Handler(http.StripPrefix("/api",
		a.store.AuthorisationChecks(authorizedPages,
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/app", http.StatusSeeOther)
			},
			func(w http.ResponseWriter, r *http.Request, sess SessionEntry) bool {
				user := a.getAuthenticatedUser(r)

				if user == nil {
					a.store.DeleteSession(w, r)
					http.Redirect(w, r, "/app", http.StatusSeeOther)
					return false
				}

				return true

			})))

	// Callback routes
	//r.HandleFunc("POST /api/record_injection", a.injectionRequestHandler)

	srv := &http.Server{
		Handler:      a.securityHeadersMiddleware(r),
		Addr:         a.config.ListenAddress,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Listening: ", a.config.ListenAddress)

	return srv.ListenAndServe()
}
