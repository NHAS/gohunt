package application

import (
	"html/template"
	"log"
	"net/http"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/ui"
)

func (a *Application) homepage(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config), "homepage.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) app(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r,
		template.FuncMap{
			"csrfToken": func() template.HTML {
				t, _ := a.store.GenerateCSRFTokenTemplateHTML(r)
				return t
			},
			"isAdmin": func() bool {
				_, s := a.store.GetSessionFromRequest(r)
				if s == nil {
					return false
				}

				var newUser models.User
				if err := a.db.Where("uuid = ?", s.UUID).First(&newUser).Error; err != nil {
					return false
				}
				return newUser.IsAdmin
			},
		},
		models.UIOptions(a.config), "mainapp_collected_pages.htm", "mainapp_payloads.htm", "mainapp_admin_users.htm", "mainapp_settings.htm", "mainapp_xss_fires.htm", "mainapp.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) features(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config), "features.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) signup(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config), "signup.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) contact(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config), "contact.htm"); err != nil {
		log.Println("failed: ", err)
	}
}
