package application

import (
	"log"
	"net/http"

	"github.com/NHAS/gohunt/application/models"
	"github.com/NHAS/gohunt/application/resources/ui"
)

func (a *Application) homepage(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config.Domain, a.config.Features.Contact.Enabled, a.config.Features.Signup.Enabled), "homepage.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) app(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config.Domain, a.config.Features.Contact.Enabled, a.config.Features.Signup.Enabled), "mainapp_collected_pages.htm", "mainapp_payloads.htm", "mainapp_settings.htm", "mainapp_xss_fires.htm", "mainapp.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) features(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config.Domain, a.config.Features.Contact.Enabled, a.config.Features.Signup.Enabled), "features.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) signup(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config.Domain, a.config.Features.Contact.Enabled, a.config.Features.Signup.Enabled), "signup.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) contact(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, models.UIOptions(a.config.Domain, a.config.Features.Contact.Enabled, a.config.Features.Signup.Enabled), "contact.htm"); err != nil {
		log.Println("failed: ", err)
	}
}
