package notifications

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"path/filepath"
)

var (
	//go:embed *htm *md *txt
	templates embed.FS
)

func Render(funcs template.FuncMap, model interface{}, content string) (string, error) {

	name := filepath.Base(content)

	var (
		parsed *template.Template
		err    error
	)
	if funcs != nil {
		parsed, err = template.New(name).Funcs(funcs).ParseFS(templates, content)
	} else {
		parsed, err = template.New(name).ParseFS(templates, content)
	}

	if err != nil {
		return "", fmt.Errorf("parse %s: %v", content, err)
	}

	buff := bytes.NewBuffer(nil)

	if err := parsed.Execute(buff, model); err != nil {
		return "", fmt.Errorf("execute %s: %v", content, err)
	}

	return string(buff.Bytes()), nil
}
