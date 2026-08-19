package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/parallel"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/ports"
)

func TestGenerateUsesSafeFilename(t *testing.T) {
	outputDir := t.TempDir()
	rep := &Reporter{OutputDir: outputDir}
	result := &parallel.ScanResult{
		Domain:    "../../bad/example.com",
		StartTime: time.Unix(0, 0),
		Errors:    make(map[parallel.ModuleType]error),
	}

	path, err := rep.Generate(result, FormatJSON)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if filepath.Dir(path) != outputDir {
		t.Fatalf("Generate wrote outside output dir: %s", path)
	}

	base := filepath.Base(path)
	if strings.Contains(base, "..") || strings.ContainsAny(base, `/\`) {
		t.Fatalf("unsafe report filename: %q", base)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected report to be written: %v", err)
	}
}

func TestGroupVulnerabilitiesBySeverityPreservesOrder(t *testing.T) {
	vuln := func(severity, name string) *nuclei.Finding {
		return &nuclei.Finding{
			TemplateID: "template-" + name,
			Info: nuclei.TemplateInfo{
				Name:     name,
				Severity: severity,
			},
			Host: "example.com",
		}
	}

	grouped := groupVulnerabilitiesBySeverity(&parallel.ScanResult{
		Vulnerabilities: []*nuclei.Finding{
			vuln("high", "high-1"),
			vuln("critical", "critical-1"),
			vuln("HIGH", "high-2"),
			vuln("medium", "medium-1"),
			vuln("low", "low-1"),
			vuln("info", "info-1"),
			vuln("unknown", "unknown-1"),
		},
	})

	if grouped.Total != 7 {
		t.Fatalf("expected total 7, got %d", grouped.Total)
	}
	assertVulnNames(t, grouped.Critical, "critical-1")
	assertVulnNames(t, grouped.High, "high-1", "high-2")
	assertVulnNames(t, grouped.Medium, "medium-1")
	assertVulnNames(t, grouped.Low, "low-1")
	assertVulnNames(t, grouped.Info, "info-1")
}

func assertVulnNames(t *testing.T, vulns []*nuclei.Finding, names ...string) {
	t.Helper()
	if len(vulns) != len(names) {
		t.Fatalf("expected %d vulnerabilities, got %d", len(names), len(vulns))
	}
	for i, name := range names {
		if vulns[i].Info.Name != name {
			t.Fatalf("expected vulnerability %d to be %q, got %q", i, name, vulns[i].Info.Name)
		}
	}
}

func TestParseFormat(t *testing.T) {
	got, err := ParseFormat("MD")
	if err != nil || got != FormatMarkdown {
		t.Fatalf("ParseFormat(MD) = %q, %v", got, err)
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Fatal("expected error for pdf")
	}
}

func TestOpenPortCountUsesOpenPortsNotHosts(t *testing.T) {
	rep := &Reporter{OutputDir: t.TempDir()}
	result := &parallel.ScanResult{
		Domain:    "example.com",
		StartTime: time.Unix(0, 0),
		Errors:    make(map[parallel.ModuleType]error),
		Ports: []*ports.Result{
			{Host: "a.example.com", OpenPorts: []ports.Port{{Port: 80}, {Port: 443}}},
			{Host: "b.example.com"},
		},
	}
	if result.OpenPortCount() != 2 {
		t.Fatalf("OpenPortCount = %d, want 2", result.OpenPortCount())
	}
	content, err := rep.generateJSON(result)
	if err != nil {
		t.Fatalf("generateJSON: %v", err)
	}
	if !strings.Contains(content, `"open_port_count": 2`) {
		t.Fatalf("json missing open_port_count 2: %s", content)
	}
}