package ui

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

var (
	//go:embed static/*/*
	static embed.FS

	//go:embed templates/*
	templates embed.FS
)

func Static(w http.ResponseWriter, r *http.Request) {

	path := strings.TrimPrefix(r.URL.Path, "/")
	fileContent, err := static.ReadFile(path)
	if err != nil {
		log.Println(err)
		http.NotFound(w, r)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", mime.TypeByExtension(filepath.Ext(path)))

	w.Write(fileContent)
}

func RenderDefaults(w http.ResponseWriter, r *http.Request, funcs template.FuncMap, model interface{}, content ...string) error {

	contentPath := []string{"templates/footer.htm", "templates/navbar.htm", "templates/header.htm"}
	for _, path := range content {
		contentPath = append(contentPath, "templates/"+path)
	}

	return Render(w, r, funcs, model, contentPath...)

}

func Render(w http.ResponseWriter, r *http.Request, funcs template.FuncMap, model interface{}, content ...string) error {

	name := ""
	if len(content) > 0 {
		name = filepath.Base(content[len(content)-1])
	}

	var (
		parsed *template.Template
		err    error
	)
	if funcs != nil {
		parsed, err = template.New(name).Funcs(funcs).ParseFS(templates, content...)
	} else {
		parsed, err = template.New(name).ParseFS(templates, content...)
	}

	if err != nil {
		return fmt.Errorf("parse %s: %v", content, err)
	}

	if err := parsed.Execute(w, model); err != nil {
		return fmt.Errorf("execute %s: %v", content, err)
	}

	return nil
}
