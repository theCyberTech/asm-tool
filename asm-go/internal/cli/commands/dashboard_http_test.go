package commands

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteDashboardInternalErrorReturnsGenericMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDashboardInternalError(rec, "Failed to load data", errors.New("sqlite: no such table: secrets"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	if strings.Contains(body, "sqlite") || strings.Contains(body, "secrets") {
		t.Fatalf("body = %q, leaked internal error details", body)
	}
	if !strings.Contains(body, "Failed to load data") {
		t.Fatalf("body = %q, want public message", body)
	}
}
