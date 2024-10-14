package home

import (
	"net/http"

	"github.com/milijan-mosic/goblin_cave/src/utils"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "My Go Website",
	}

	utils.RenderTemplate(w, "/home/index", data)
}
