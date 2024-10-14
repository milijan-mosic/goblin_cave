package utils

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

var (
	baseTemplatePath = "./templates/base.html"
)

func RenderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	templateFiles := []string{
		filepath.Join("./templates", templateName+".html"),
		baseTemplatePath,
	}

	template, err := template.ParseFiles(templateFiles...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("Error parsing templates -> ", err)
		return
	}

	err = template.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("Error executing template -> ", err)
	}
}
