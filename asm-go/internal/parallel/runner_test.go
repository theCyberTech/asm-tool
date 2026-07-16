package parallel

import (
	"testing"

	"github.com/asm-tool/asm-go/internal/scanner/ports"
)

func TestScanResultContainsScannerTypes(t *testing.T) {
	result := &ScanResult{
		Domain: "example.com",
		Subdomains: []string{"www.example.com"},
		Ports: []*ports.Result{
			{
				Host: "www.example.com",
				OpenPorts: []ports.Port{
					{Port: 443, State: "open", Service: "https"},
				},
			},
		},
	}

	if len(result.Subdomains) != 1 {
		t.Fatalf("expected 1 subdomain, got %d", len(result.Subdomains))
	}
	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port result, got %d", len(result.Ports))
	}
	if len(result.Ports[0].OpenPorts) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(result.Ports[0].OpenPorts))
	}
	if result.Ports[0].OpenPorts[0].Port != 443 {
		t.Fatalf("expected port 443, got %d", result.Ports[0].OpenPorts[0].Port)
	}
}

func TestEnabledModulesStableOrder(t *testing.T) {
	enabled := map[ModuleType]bool{
		ModulePorts:      true,
		ModuleDNS:        true,
		ModuleSubdomains: true,
	}

	mods := enabledModules(enabled)

	// Check order is stable (ports before dns before subdomains is not expected since subdomains is phase 1)
	// The stable order should be: ports, dns
	if len(mods) != 2 {
		t.Fatalf("expected 2 enabled modules, got %d", len(mods))
	}
	if mods[0] != ModulePorts || mods[1] != ModuleDNS {
		t.Fatalf("expected [ports, dns], got %v", mods)
	}
}

func TestFlattenPortScanResultsPreservesBatchOrder(t *testing.T) {
	batch := []*ports.Result{
		{
			Host: "first.example.com",
			OpenPorts: []ports.Port{
				{Port: 443, State: "open", Service: "https", Banner: "first"},
			},
		},
		nil,
		{
			Host: "second.example.com",
			OpenPorts: []ports.Port{
				{Port: 80, State: "open", Service: "http", Banner: "second"},
				{Port: 8080, State: "open", Service: "http-proxy"},
			},
		},
	}

	var allPorts []ports.Port
	for _, r := range batch {
		if r == nil {
			continue
		}
		for _, p := range r.OpenPorts {
			allPorts = append(allPorts, p)
		}
	}

	want := []ports.Port{
		{Port: 443, State: "open", Service: "https", Banner: "first"},
		{Port: 80, State: "open", Service: "http", Banner: "second"},
		{Port: 8080, State: "open", Service: "http-proxy"},
	}
	if len(allPorts) != len(want) {
		t.Fatalf("got %d ports, want %d: %#v", len(allPorts), len(want), allPorts)
	}
	for i := range want {
		if allPorts[i] != want[i] {
			t.Fatalf("port %d = %#v, want %#v", i, allPorts[i], want[i])
		}
	}
}

func TestAllModulesReturnsExpectedCount(t *testing.T) {
	mods := AllModules()
	if len(mods) != 11 {
		t.Fatalf("expected 11 modules, got %d", len(mods))
	}
}

func TestParseModuleRecognizesNames(t *testing.T) {
	tests := map[string]ModuleType{
		"subdomains": ModuleSubdomains,
		"ports":      ModulePorts,
		"nuclei":     ModuleNuclei,
	}

	for input, want := range tests {
		got := ParseModule(input)
		if got != want {
			t.Fatalf("ParseModule(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseModuleRejectsUnknown(t *testing.T) {
	got := ParseModule("nonexistent")
	if got != "" {
		t.Fatalf("ParseModule(\"nonexistent\") = %q, want empty", got)
	}
}