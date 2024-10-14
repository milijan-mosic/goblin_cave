package main

import (
	"log"
	"net/http"

	"github.com/milijan-mosic/goblin_cave/controllers/home"
)

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/", home.IndexHandler)

	log.Println("Starting server on :10000...")
	if err := http.ListenAndServe(":10000", nil); err != nil {
		log.Fatal(err)
	}
}
