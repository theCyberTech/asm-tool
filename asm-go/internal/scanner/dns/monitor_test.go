package dns

import (
	"testing"
)

func TestDetectChanges_NoChanges(t *testing.T) {
	curr := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4", TTL: 300}},
		},
	}
	prev := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4", TTL: 300}},
		},
	}
	changes := DetectChanges(curr, prev)
	if len(changes) != 0 {
		t.Errorf("expected no changes, got %d: %+v", len(changes), changes)
	}
}

func TestDetectChanges_RecordAdded(t *testing.T) {
	curr := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4"}, {Type: "A", Value: "5.6.7.8"}},
		},
	}
	prev := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4"}},
		},
	}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "record_added" || changes[0].NewValue != "5.6.7.8" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestDetectChanges_RecordRemoved(t *testing.T) {
	curr := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4"}},
		},
	}
	prev := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4"}, {Type: "A", Value: "9.9.9.9"}},
		},
	}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "record_removed" || changes[0].OldValue != "9.9.9.9" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestDetectChanges_SOASerialChanged(t *testing.T) {
	curr := &Result{Records: make(map[string][]Record), SOA: &SOARecord{Serial: 2024010102}}
	prev := &Result{Records: make(map[string][]Record), SOA: &SOARecord{Serial: 2024010101}}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Type != "soa_serial_changed" {
		t.Errorf("expected soa_serial_changed, got %s", changes[0].Type)
	}
}

func TestDetectChanges_DNSSECStatusChanged(t *testing.T) {
	curr := &Result{Records: make(map[string][]Record), DNSSEC: &DNSSECResult{Signed: true}}
	prev := &Result{Records: make(map[string][]Record), DNSSEC: &DNSSECResult{Signed: false}}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Type != "record_changed" || changes[0].RecordType != "DNSSEC" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestDetectChanges_NilPrevious(t *testing.T) {
	curr := &Result{
		Records: map[string][]Record{
			"A": {{Type: "A", Value: "1.2.3.4"}},
		},
	}
	changes := DetectChanges(curr, nil)
	if changes != nil {
		t.Errorf("expected nil for first scan, got %v", changes)
	}
}

func TestDetectChanges_CAAAdded(t *testing.T) {
	// CAA record in curr but not in prev → it was added
	curr := &Result{
		Records: make(map[string][]Record),
		CAA:     []CAARecord{{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
	}
	prev := &Result{Records: make(map[string][]Record)}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "record_added" || changes[0].RecordType != "CAA" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestDetectChanges_CAARemoved(t *testing.T) {
	// CAA record was in prev but gone from curr → removed
	curr := &Result{Records: make(map[string][]Record)}
	prev := &Result{
		Records: make(map[string][]Record),
		CAA:     []CAARecord{{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
	}
	changes := DetectChanges(curr, prev)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "record_removed" || changes[0].RecordType != "CAA" {
		t.Errorf("unexpected change: %+v", changes[0])
	}
}

func TestSetDiff(t *testing.T) {
	tests := []struct {
		a, b []string
		want []string
	}{
		{[]string{"a", "b", "c"}, []string{"b"}, []string{"a", "c"}},
		{[]string{"a"}, []string{"a"}, nil},
		{nil, []string{"a"}, nil},
		{[]string{"a"}, nil, []string{"a"}},
	}
	for _, tt := range tests {
		got := setDiff(tt.a, tt.b)
		if len(got) != len(tt.want) {
			t.Errorf("setDiff(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			continue
		}
		// Check all elements
		wantSet := make(map[string]bool)
		for _, v := range tt.want {
			wantSet[v] = true
		}
		for _, v := range got {
			if !wantSet[v] {
				t.Errorf("unexpected element %s in setDiff result", v)
			}
		}
	}
}
