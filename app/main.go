package main

import (
	"log"
	"net/http"

	_ "github.com/milijan-mosic/goblin_cave/docs"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/milijan-mosic/goblin_cave/controllers/home"
)

// @title API
// @version 1.0
// @description This is a sample API documentation.
// @host app.goblin.local
// @BasePath /api/v1

// @Summary Get user by ID
// @Description Retrieves a user by their ID.
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200
// @Failure 400
// @Router /test [get]
func testAPI(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"id": 1, "name": "John Doe"}`))
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.Handle("/swagger/", httpSwagger.WrapHandler)

	http.HandleFunc("/", home.IndexHandler)
	http.HandleFunc("/api/v1/test", testAPI)

	log.Println("Starting server on :10000...")
	if err := http.ListenAndServe(":10000", nil); err != nil {
		log.Fatal(err)
	}
}
