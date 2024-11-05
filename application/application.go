package application

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/ui"
	"github.com/NHAS/gohunt/config"

	"github.com/NHAS/session"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SessionEntry struct {
	UUID uuid.UUID
}

type Application struct {
	config config.Config

	store               *session.SessionStore[SessionEntry]
	db                  *gorm.DB
	forbiddenSubdomains []string
}

func New(c config.Config) (*Application, error) {

	var newApplication = Application{
		config:              c,
		forbiddenSubdomains: []string{"www", "api"},
	}

	var err error
	newApplication.store, err = session.NewStore[SessionEntry]("session", "X-CSRF-Token", 8*time.Hour, 86400, false)
	if err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", c.Database.Host, c.Database.Port, c.Database.User, c.Database.Password, c.Database.DBname, c.Database.SSLmode)

	db, err := gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %s", err)
	}
	db.AutoMigrate(&models.User{}, &models.Injection{}, &models.InjectionRequest{}, &models.CollectedPage{})

	newApplication.db = db

	return &newApplication, nil
}

func (a *Application) Run() error {

	r := http.NewServeMux()

	// Public API routes
	r.HandleFunc("POST /api/register", a.registerHandler)
	r.HandleFunc("POST /api/login", a.loginHandler)
	r.HandleFunc("POST /api/contactus", a.contactUsHandler)

	// Health check
	r.HandleFunc("GET /health", a.healthHandler)

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

	r.Handle("/api/", http.StripPrefix("/api", a.store.AuthorisationChecks(authorizedPages,
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

	// Handles both post and options
	r.HandleFunc("/js_callback", a.callbackHandler)
	r.HandleFunc("/page_callback", a.collectPageHandler)

	// UI Routes
	r.HandleFunc("/", a.homepage)
	r.HandleFunc("GET /app", a.app)
	r.HandleFunc("GET /features", a.features)
	r.HandleFunc("GET /signup", a.signup)
	r.HandleFunc("GET /contact", a.contact)
	r.HandleFunc("GET /static/", ui.Static)

	srv := &http.Server{
		Handler:      a.securityHeadersMiddleware(r),
		Addr:         a.config.ListenAddress,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Listening: ", a.config.ListenAddress)

	return srv.ListenAndServe()
}
