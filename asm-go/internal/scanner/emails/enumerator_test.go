package emails

import (
	"context"
	"testing"
	"time"
)

type stubEmailSource struct {
	name   string
	emails []string
}

func (s *stubEmailSource) Name() string { return s.name }

func (s *stubEmailSource) Enumerate(context.Context, string) ([]string, error) {
	return s.emails, nil
}

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

func TestEmailFromSourceLabelsPermutatorAsGuessed(t *testing.T) {
	got := emailFromSource("support@example.com", "example.com", "permutator")
	if got.Type != "guessed" {
		t.Fatalf("Type = %q, want guessed", got.Type)
	}
	if got.Verified {
		t.Fatal("permutator emails must not be marked verified")
	}
	if got.Source != "permutator" {
		t.Fatalf("Source = %q, want permutator", got.Source)
	}

	other := emailFromSource("support@example.com", "example.com", "github")
	if other.Type != "role" {
		t.Fatalf("non-permutator Type = %q, want role", other.Type)
	}
	if other.Verified {
		t.Fatal("Verified should default to false")
	}
}

func TestEnumeratePermutatorLabeledGuessed(t *testing.T) {
	enum := &Enumerator{
		Sources: []Source{
			&stubEmailSource{name: "permutator", emails: []string{"support@example.com", "jane.doe@example.com"}},
		},
		Timeout: 5 * time.Second,
	}
	result := enum.Enumerate(context.Background(), "example.com")
	if len(result.Emails) != 2 {
		t.Fatalf("got %d emails, want 2: %+v", len(result.Emails), result.Emails)
	}
	for _, email := range result.Emails {
		if email.Type != "guessed" {
			t.Fatalf("%s Type = %q, want guessed", email.Address, email.Type)
		}
		if email.Verified {
			t.Fatalf("%s should not be verified", email.Address)
		}
		if email.Source != "permutator" {
			t.Fatalf("%s Source = %q, want permutator", email.Address, email.Source)
		}
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
