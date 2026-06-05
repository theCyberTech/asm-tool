package emails

import (
	"context"
	"testing"
)

func TestDefaultEnumeratorIncludesHunterSource(t *testing.T) {
	enum := DefaultEnumerator()

	foundHunter := false
	for _, src := range enum.Sources {
		if _, ok := src.(*HunterSource); ok {
			foundHunter = true
			break
		}
	}

	if !foundHunter {
		t.Fatal("default enumerator should include Hunter source")
	}
}

func TestHunterSourceWithoutAPIKeyReturnsError(t *testing.T) {
	hunter := &HunterSource{}
	_, err := hunter.Enumerate(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Hunter without API key should return error")
	}
}

func TestClassifyEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "exact role address",
			email: "support@example.com",
			want:  "role",
		},
		{
			name:  "role address with dotted prefix",
			email: "emea.support@example.com",
			want:  "role",
		},
		{
			name:  "generic address pattern",
			email: "weekly-newsletter@example.com",
			want:  "generic",
		},
		{
			name:  "personal address",
			email: "jane.doe@example.com",
			want:  "personal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyEmail(tt.email); got != tt.want {
				t.Fatalf("classifyEmail(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestEmailPermutatorGeneratesCommonPatterns(t *testing.T) {
	source := &EmailPermutatorSource{}
	// Use a domain known to have MX records. In CI environments DNS may be
	// unavailable so we skip if MX lookup fails.
	emails, err := source.Enumerate(context.Background(), "gmail.com")
	if err != nil {
		t.Fatalf("Enumerate returned error: %v", err)
	}
	if len(emails) == 0 {
		t.Skip("MX lookup failed or returned no records; skipping permutation test")
	}

	// Should generate common role-based emails
	found := make(map[string]bool)
	for _, e := range emails {
		found[e] = true
	}

	required := []string{"info@gmail.com", "support@gmail.com", "sales@gmail.com", "admin@gmail.com"}
	for _, r := range required {
		if !found[r] {
			t.Fatalf("Expected %s in generated emails", r)
		}
	}
}
