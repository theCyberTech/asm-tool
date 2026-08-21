package dashboard

import (
	"encoding/json"
	"testing"
)

func TestOverviewJSONUsesEmptySlices(t *testing.T) {
	body, err := json.Marshal(OverviewJSON(PageData{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := payload["domains"].([]any); !ok {
		t.Fatalf("domains = %T, want array", payload["domains"])
	}
	if _, ok := payload["change_events"].([]any); !ok {
		t.Fatalf("change_events = %T, want array", payload["change_events"])
	}
}

func TestDomainDetailJSONPromotesCanonicalFields(t *testing.T) {
	payload := DomainDetailJSON(PageData{
		DomainDetail: &DomainDetailData{Domain: "example.com"},
	})
	if payload.Status != "ok" || payload.Domain != "example.com" {
		t.Fatalf("payload = %+v", payload)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Subdomains []any `json:"subdomains"`
		Ports      []any `json:"ports"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Subdomains == nil || decoded.Ports == nil {
		t.Fatalf("expected empty arrays, got subdomains=%v ports=%v", decoded.Subdomains, decoded.Ports)
	}
}
