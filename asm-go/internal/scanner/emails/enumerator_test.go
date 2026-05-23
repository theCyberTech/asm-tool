package emails

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)


func TestHunterSourceSendsAPIKeyInHeaderNotURL(t *testing.T) {
	t.Parallel()

	const apiKey = "secret-hunter-key"

	source := &HunterSource{
		client: &http.Client{
			Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.RawQuery, "api_key") {
					t.Error("Hunter API key must not appear in the request URL")
				}
				if got := r.Header.Get("X-API-KEY"); got != apiKey {
				t.Fatalf("X-API-KEY header = %q, want %q", got, apiKey)
				}
				if got := r.URL.Query().Get("domain"); got != "example.com" {
				t.Fatalf("domain query param = %q, want example.com", got)
				}

				rec := httptest.NewRecorder()
				_ = json.NewEncoder(rec).Encode(map[string]any{
					"data": map[string]any{
						"emails": []map[string]string{
							{"value": "found@example.com"},
						},
					},
				})
				return rec.Result(), nil
			}),
		},
		APIKey: apiKey,
	}

	emails, err := source.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}
	if len(emails) != 1 || emails[0] != "found@example.com" {
		t.Fatalf("Enumerate() = %#v, want [found@example.com]", emails)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestDefaultEnumeratorWithHunterAPIKeyConfiguresHunterSource(t *testing.T) {
	enum := DefaultEnumeratorWithHunterAPIKey(" hunter-key ")

	foundHunter := false
	for _, src := range enum.Sources {
		hunter, ok := src.(*HunterSource)
		if !ok {
			continue
		}
		foundHunter = true
		if hunter.APIKey != "hunter-key" {
		t.Fatalf("Hunter API key = %q, want hunter-key", hunter.APIKey)
		}
	}

	if !foundHunter {
		t.Fatal("default enumerator did not include Hunter source")
	}
}
