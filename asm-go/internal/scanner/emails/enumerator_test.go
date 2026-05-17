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
