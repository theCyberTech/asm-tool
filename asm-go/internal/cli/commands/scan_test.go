package commands

import (
	"strings"
	"testing"
)

func TestRunFullScanRejectsInvalidDomainBeforeScanning(t *testing.T) {
	err := runFullScan(nil, nil, "example.com/path", scanOptions{})
	if err == nil {
		t.Fatal("runFullScan accepted an invalid domain")
	}
	if !strings.Contains(err.Error(), "invalid target domain") {
		t.Fatalf("runFullScan error = %q, want invalid target domain", err.Error())
	}
}
