package application

import (
	"net/http"

	"github.com/NHAS/gohunt/application/resources/attack"
)

func (a *Application) probe(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/javascript")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, DELETE, POST, GET")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Origin, Authorization, Accept, Accept-Encoding")

	user, err := a.getUserFromSubdomain(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Write(attack.NewProbe(r.Host, r.URL.Path, *user))
}
