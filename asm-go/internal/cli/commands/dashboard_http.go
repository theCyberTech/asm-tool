package commands

import (
	"log"
	"net/http"
)

func writeDashboardInternalError(w http.ResponseWriter, message string, err error) {
	log.Printf("dashboard: %s: %v", message, err)
	http.Error(w, message, http.StatusInternalServerError)
}

func writeDashboardBadRequest(w http.ResponseWriter, err error) {
	log.Printf("dashboard: bad request: %v", err)
	http.Error(w, err.Error(), http.StatusBadRequest)
}
