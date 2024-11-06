package application

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/ui"
	"github.com/NHAS/gohunt/config"
	"github.com/gorilla/mux"

	"github.com/NHAS/session"
	"github.com/google/uuid"
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

	return &newApplication, nil
}

func (a *Application) Run() error {

	r := mux.NewRouter()

	r.HandleFunc("/check_domain", a.allowedDomain)

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
	managementDomain.HandleFunc("/signup", a.signup).Methods("GET")
	managementDomain.HandleFunc("/contact", a.contact).Methods("GET")
	managementDomain.PathPrefix("/static/").HandlerFunc(ui.Static).Methods("GET")

	// Public API routes
	managementDomain.HandleFunc("/api/register", a.registerHandler).Methods("POST")
	managementDomain.HandleFunc("/api/login", a.loginHandler).Methods("POST")
	managementDomain.HandleFunc("/api/contactus", a.contactUsHandler).Methods("POST")

	// Health check
	managementDomain.HandleFunc("/health", a.healthHandler).Methods("GET")

	// Authorisation required API routes
	authorizedPages := http.NewServeMux()
	authorizedPages.HandleFunc("GET /collected_pages", a.getCollectedPagesHandler)
	authorizedPages.HandleFunc("DELETE /delete_injection", a.deleteInjectionHandler)
	authorizedPages.HandleFunc("DELETE /delete_collected_page", a.deleteCollectedPageHandler)
	authorizedPages.HandleFunc("GET /user", a.userInformationHandler)
	authorizedPages.HandleFunc("PUT /user", a.editUserInformationHandler)
	authorizedPages.HandleFunc("GET /payloadfires", a.getXSSPayloadFiresHandler)
	authorizedPages.HandleFunc("POST /resend_injection_email", a.resendInjectionEmailHandler)
	authorizedPages.HandleFunc("GET /logout", a.logoutHandler)

	managementDomain.PathPrefix("/api/").Handler(http.StripPrefix("/api", a.store.AuthorisationChecks(authorizedPages,
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/app", http.StatusSeeOther)
		},
		func(w http.ResponseWriter, r *http.Request, sess SessionEntry) bool {
			if a.getAuthenticatedUser(r) == nil {
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
