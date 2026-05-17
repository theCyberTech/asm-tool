package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/parallel"
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
	vuln := func(severity, name string) *parallel.VulnFinding {
		return &parallel.VulnFinding{
			TemplateID: "template-" + name,
			Info: parallel.VulnInfo{
				Name:     name,
				Severity: severity,
			},
			Host: "example.com",
		}
	}

	grouped := groupVulnerabilitiesBySeverity(&parallel.ScanResult{
		Vulnerabilities: []*parallel.VulnFinding{
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

func assertVulnNames(t *testing.T, vulns []*parallel.VulnFinding, names ...string) {
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
