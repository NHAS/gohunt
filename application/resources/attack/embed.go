package attack

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/NHAS/gohunt/application/models"
)

var (
	//go:embed probe.js
	embedProbe []byte

	//go:embed pgp_encrypted_template.txt
	pgpTemplate []byte
)

func NewProbe(numbProxies int, r *http.Request, user models.User) []byte {

	scheme := "https://"
	if numbProxies > 0 {
		potentialScheme := r.Header.Get("X-Forwarded-Proto")
		if potentialScheme != "" {
			scheme = potentialScheme + "://"
		}
	} else {
		if r.TLS == nil {
			scheme = "http://"
		}
	}

	newProbe := bytes.ReplaceAll(embedProbe, []byte("[HOST_URL]"), []byte(scheme+r.Host))

	pgpKey, _ := json.Marshal(user.PGPKey)
	newProbe = bytes.ReplaceAll(newProbe, []byte("[PGP_REPLACE_ME]"), []byte(pgpKey))

	chainloadURI, _ := json.Marshal(user.ChainloadURI)
	newProbe = bytes.ReplaceAll(newProbe, []byte("[CHAINLOAD_REPLACE_ME]"), []byte(chainloadURI))

	collectionPaths, _ := json.Marshal(user.PageCollectionPaths)
	newProbe = bytes.ReplaceAll(newProbe, []byte("[COLLECT_PAGE_LIST_REPLACE_ME]"), []byte(collectionPaths))

	pgpTemplateReplace, _ := json.Marshal("")
	if user.PGPKey != "" {
		pgpTemplateReplace, _ = json.Marshal(string(pgpTemplate))
	}
	newProbe = bytes.ReplaceAll(newProbe, []byte("[TEMPLATE_REPLACE_ME]"), []byte(pgpTemplateReplace))

	parts := strings.Split(r.URL.Path, "/")
	if r.URL.Path != "/" && len(parts) > 1 {
		newProbe = bytes.ReplaceAll(newProbe, []byte("[PROBE_ID]"), []byte(parts[1]))
	}

	return newProbe
}
