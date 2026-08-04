package commands

import "testing"

func TestNormalizeDomainList(t *testing.T) {
	got, err := normalizeDomainList([]string{" Example.COM. ", "api.example.com"})
	if err != nil {
		t.Fatalf("normalizeDomainList returned error: %v", err)
	}

	want := []string{"example.com", "api.example.com"}
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
	for _, input := range []string{"https://example.com", "example.com/path", "example.com?query=1"} {
		if _, err := normalizeDomainList([]string{input}); err == nil {
			t.Errorf("normalizeDomainList(%q) succeeded, want error", input)
		}
	}
}
