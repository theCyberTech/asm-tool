package commands

import (
	"encoding/json"
	"testing"
)

func TestDiffSubdomainsDetectsAddedAndRemoved(t *testing.T) {
	prev := []string{"a.example.com", "b.example.com", "c.example.com"}
	curr := []string{"b.example.com", "c.example.com", "d.example.com"}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	diff := diffSubdomains(string(prevJSON), string(currJSON))
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if len(diff.Added) != 1 || diff.Added[0] != "d.example.com" {
		t.Fatalf("added = %v, want [d.example.com]", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != "a.example.com" {
		t.Fatalf("removed = %v, want [a.example.com]", diff.Removed)
	}
	if diff.PrevCount != 3 || diff.CurrCount != 3 {
		t.Fatalf("counts = %d/%d, want 3/3", diff.PrevCount, diff.CurrCount)
	}
}

func TestDiffSubdomainsNoChangeReturnsNil(t *testing.T) {
	prev := []string{"a.example.com", "b.example.com"}
	curr := []string{"b.example.com", "a.example.com"}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	if diff := diffSubdomains(string(prevJSON), string(currJSON)); diff != nil {
		t.Fatalf("expected nil diff for identical sets, got %+v", diff)
	}
}

func TestDiffSubdomainsEmptyJSONReturnsDiff(t *testing.T) {
	diff := diffSubdomains("null", `["a.example.com"]`)
	if diff == nil {
		t.Fatal("expected non-nil diff when previous is null")
	}
	if len(diff.Added) != 1 {
		t.Fatalf("added = %v, want 1 entry", diff.Added)
	}
}

func TestDiffPortsDetectsNewAndClosed(t *testing.T) {
	type pe = portEntry
	prev := []pe{{Host: "a.example.com", Port: 80, Service: "http"}, {Host: "a.example.com", Port: 443, Service: "https"}}
	curr := []pe{{Host: "a.example.com", Port: 443, Service: "https"}, {Host: "a.example.com", Port: 8080, Service: "http-alt"}}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	diff := diffPorts(string(prevJSON), string(currJSON))
	if diff == nil {
		t.Fatal("expected non-nil port diff")
	}
	if len(diff.Added) != 1 || diff.Added[0].Port != 8080 {
		t.Fatalf("added = %v, want port 8080", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Port != 80 {
		t.Fatalf("removed = %v, want port 80", diff.Removed)
	}
}

func TestDiffPortsNoChangeReturnsNil(t *testing.T) {
	type pe = portEntry
	prev := []pe{{Host: "a.example.com", Port: 80, Service: "http"}}
	curr := []pe{{Host: "a.example.com", Port: 80, Service: "http"}}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	if diff := diffPorts(string(prevJSON), string(currJSON)); diff != nil {
		t.Fatalf("expected nil, got %+v", diff)
	}
}

func TestDiffVulnsDetectsNewAndResolved(t *testing.T) {
	type ve = vulnEntry
	prev := []ve{
		{TemplateID: "CVE-2024-1234", Name: "Old Vuln", Severity: "high", Host: "a.example.com"},
		{TemplateID: "CVE-2024-5678", Name: "Still Here", Severity: "medium", Host: "b.example.com"},
	}
	curr := []ve{
		{TemplateID: "CVE-2024-5678", Name: "Still Here", Severity: "medium", Host: "b.example.com"},
		{TemplateID: "CVE-2024-9999", Name: "New Vuln", Severity: "critical", Host: "a.example.com"},
	}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	diff := diffVulns(string(prevJSON), string(currJSON))
	if diff == nil {
		t.Fatal("expected non-nil vuln diff")
	}
	if len(diff.Added) != 1 || diff.Added[0].TemplateID != "CVE-2024-9999" {
		t.Fatalf("added = %v, want CVE-2024-9999", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].TemplateID != "CVE-2024-1234" {
		t.Fatalf("removed = %v, want CVE-2024-1234", diff.Removed)
	}
	if diff.Added[0].Severity != "critical" {
		t.Fatalf("added[0].Severity = %s, want critical", diff.Added[0].Severity)
	}
}

func TestDiffVulnsNoChangeReturnsNil(t *testing.T) {
	type ve = vulnEntry
	prev := []ve{{TemplateID: "X", Name: "Y", Severity: "low", Host: "h"}}
	curr := []ve{{TemplateID: "X", Name: "Y", Severity: "low", Host: "h"}}
	prevJSON, _ := json.Marshal(prev)
	currJSON, _ := json.Marshal(curr)

	if diff := diffVulns(string(prevJSON), string(currJSON)); diff != nil {
		t.Fatalf("expected nil, got %+v", diff)
	}
}
