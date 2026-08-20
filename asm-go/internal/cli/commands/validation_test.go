package commands

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/target"
)

func TestNormalizeDomainList(t *testing.T) {
	got, err := normalizeDomainList([]string{" CrewAI.COM. ", "api.crewai.com"})
	if err != nil {
		t.Fatalf("normalizeDomainList returned error: %v", err)
	}

	want := []string{"crewai.com", "api.crewai.com"}
	if len(got) != len(want) {
		t.Fatalf("normalizeDomainList returned %d domains, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("normalizeDomainList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeDomainListRejectsURLAndPath(t *testing.T) {
	for _, input := range []string{"https://crewai.com", "crewai.com/path", "crewai.com?query=1"} {
		if _, err := normalizeDomainList([]string{input}); err == nil {
			t.Errorf("normalizeDomainList(%q) succeeded, want error", input)
		}
	}
}

func TestNormalizeDomainListRejectsOutOfScope(t *testing.T) {
	_, err := normalizeDomainList([]string{"google.com"})
	if err == nil {
		t.Fatal("normalizeDomainList accepted google.com")
	}
	if !strings.Contains(err.Error(), "restricted to crewai.com") {
		t.Fatalf("error = %q, want restricted to crewai.com", err.Error())
	}
}

func TestResolveScanDomainsRejectsOutOfScope(t *testing.T) {
	_, err := resolveScanDomains(nil, []string{"google.com"}, false)
	if err == nil {
		t.Fatal("resolveScanDomains accepted google.com")
	}
	if !strings.Contains(err.Error(), "restricted to crewai.com") {
		t.Fatalf("error = %q, want restricted to crewai.com", err.Error())
	}
}

func TestResolveScanDomainsAllKnownSkipsOutOfScope(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Domains.Add("google.com"); err != nil {
		t.Fatalf("adding google.com: %v", err)
	}
	if _, err := db.Domains.Add("crewai.com"); err != nil {
		t.Fatalf("adding crewai.com: %v", err)
	}

	got, err := resolveScanDomains(db, nil, true)
	if err != nil {
		t.Fatalf("resolveScanDomains(--all-known): %v", err)
	}
	if len(got) != 1 || got[0] != target.AllowedRootDomain {
		t.Fatalf("resolveScanDomains(--all-known) = %v, want [%s]", got, target.AllowedRootDomain)
	}
}

func TestResolveScanDomainsAllKnownErrorsWhenNothingInScope(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Domains.Add("google.com"); err != nil {
		t.Fatalf("adding google.com: %v", err)
	}

	_, err = resolveScanDomains(db, nil, true)
	if err == nil {
		t.Fatal("expected error when all known domains are out of scope")
	}
	if !strings.Contains(err.Error(), "no in-scope targets") {
		t.Fatalf("error = %q, want no in-scope targets", err.Error())
	}
}

func TestNormalizeNucleiScanTarget(t *testing.T) {
	got, err := normalizeNucleiScanTarget("https://app.crewai.com/v1")
	if err != nil {
		t.Fatalf("normalizeNucleiScanTarget: %v", err)
	}
	if got != "https://app.crewai.com/v1" {
		t.Fatalf("got %q, want URL preserved", got)
	}

	if _, err := normalizeNucleiScanTarget("https://google.com"); err == nil {
		t.Fatal("normalizeNucleiScanTarget accepted https://google.com")
	}
}
