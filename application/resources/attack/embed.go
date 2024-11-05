package attack

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/NHAS/gohunt/application/models"
)

var (
	//go:embed probe.js
	embedProbe []byte

	//go:embed pgp_encrypted_template.txt
	pgpTemplate []byte
)

func NewProbe(domain, urlPath string, user models.User) []byte {
	newProbe := bytes.ReplaceAll(embedProbe, []byte("[HOST_URL]"), []byte("https://"+domain))

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

	parts := strings.Split(urlPath, "/")
	if urlPath != "/" && len(parts) > 1 {
		newProbe = bytes.ReplaceAll(newProbe, []byte("[PROBE_ID]"), []byte(parts[1]))
	}

	return newProbe
}
