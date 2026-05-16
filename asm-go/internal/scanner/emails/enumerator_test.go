package emails

import "testing"

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
