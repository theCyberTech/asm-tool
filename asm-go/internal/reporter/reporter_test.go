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
