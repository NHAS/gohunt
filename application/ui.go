package application

import (
	"log"
	"net/http"

	"github.com/NHAS/gohunt/application/resources/ui"
)

func (a *Application) homepage(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, nil, "homepage.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) app(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, struct{ Domain string }{Domain: "test"}, "mainapp_collected_pages.htm", "mainapp_payloads.htm", "mainapp_settings.htm", "mainapp_xss_fires.htm", "mainapp.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) features(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, struct{ Domain string }{Domain: "test"}, "features.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) signup(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, struct{ Domain string }{Domain: "test"}, "signup.htm"); err != nil {
		log.Println("failed: ", err)
	}
}

func (a *Application) contact(w http.ResponseWriter, r *http.Request) {
	if err := ui.RenderDefaults(w, r, nil, struct{ Domain string }{Domain: "test"}, "contact.htm"); err != nil {
		log.Println("failed: ", err)
	}
}
