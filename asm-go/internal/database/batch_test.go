package database

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestValuePlaceholders(t *testing.T) {
	if got := valuePlaceholders(0, 2); got != "" {
		t.Errorf("valuePlaceholders(0, 2) = %q, want empty", got)
	}
	if got := valuePlaceholders(1, 2); got != "(?,?)" {
		t.Errorf("valuePlaceholders(1, 2) = %q, want (?,?)", got)
	}
	if got := valuePlaceholders(3, 2); got != "(?,?),(?,?),(?,?)" {
		t.Errorf("valuePlaceholders(3, 2) = %q", got)
	}
	if got := valuePlaceholders(2, 5); got != "(?,?,?,?,?),(?,?,?,?,?)" {
		t.Errorf("valuePlaceholders(2, 5) = %q", got)
	}
}

func TestInsertBatchSize(t *testing.T) {
	if got := insertBatchSize(5); got != sqliteMaxVars/5 {
		t.Errorf("insertBatchSize(5) = %d, want %d", got, sqliteMaxVars/5)
	}
	if got := insertBatchSize(0); got != 1 {
		t.Errorf("insertBatchSize(0) = %d, want 1", got)
	}
}

func TestAddSubdomainsBatch(t *testing.T) {
	db := newTestDB(t)

	domain, err := db.Domains.Add("example.com")
	if err != nil {
		t.Fatalf("Add domain: %v", err)
	}

	subs := make([]string, 250)
	for i := range subs {
		subs[i] = fmt.Sprintf("s%d.example.com", i)
	}
	subs = append(subs, "s0.example.com", "") // duplicate + empty should be ignored

	if err := db.Domains.AddSubdomains(domain.ID, subs); err != nil {
		t.Fatalf("AddSubdomains: %v", err)
	}

	got, err := db.Domains.GetSubdomains(domain.ID)
	if err != nil {
		t.Fatalf("GetSubdomains: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("got %d subdomains, want 250", len(got))
	}

	// Upsert should keep the row active and succeed on a second write.
	if err := db.Domains.AddSubdomains(domain.ID, []string{"s0.example.com"}); err != nil {
		t.Fatalf("AddSubdomains upsert: %v", err)
	}
}

func TestAddAllPortsBatch(t *testing.T) {
	db := newTestDB(t)

	ports := make([]Port, 0, 200)
	for i := 0; i < 200; i++ {
		ports = append(ports, Port{
			Host:     fmt.Sprintf("h%d.example.com", i/2),
			Port:     80 + (i % 2),
			Protocol: "tcp",
			Service:  "http",
			State:    "open",
			Banner:   "nginx",
		})
	}
	// Duplicate of the first row with an updated banner should win.
	ports = append(ports, Port{
		Host:     "h0.example.com",
		Port:     80,
		Protocol: "tcp",
		Service:  "http",
		State:    "open",
		Banner:   "updated",
	})

	if err := db.Ports.AddAll(ports); err != nil {
		t.Fatalf("AddAll: %v", err)
	}

	got, err := db.Ports.GetByHost("h0.example.com")
	if err != nil {
		t.Fatalf("GetByHost: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d ports for h0, want 2", len(got))
	}
	foundUpdated := false
	for _, p := range got {
		if p.Port == 80 && p.Banner == "updated" {
			foundUpdated = true
		}
	}
	if !foundUpdated {
		t.Fatal("expected duplicate port row to keep the last banner")
	}
}

func TestSaveURLsBatch(t *testing.T) {
	db := newTestDB(t)

	records := make([]URLRecord, 0, 250)
	for i := 0; i < 250; i++ {
		records = append(records, URLRecord{
			Domain:      "example.com",
			URL:         fmt.Sprintf("https://example.com/p/%d", i),
			Category:    "page",
			Source:      "wayback",
			Interesting: 0,
		})
	}
	records = append(records, URLRecord{
		Domain:      "example.com",
		URL:         "https://example.com/p/0",
		Category:    "api",
		Source:      "urlscan",
		Interesting: 1,
	})

	if err := db.SaveURLs(records); err != nil {
		t.Fatalf("SaveURLs: %v", err)
	}

	got, err := db.GetURLsForDomain("example.com")
	if err != nil {
		t.Fatalf("GetURLsForDomain: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("got %d URLs, want 250", len(got))
	}

	var found bool
	for _, u := range got {
		if u.URL == "https://example.com/p/0" {
			found = true
			if u.Category.String != "api" || u.Interesting != 1 || u.Source != "urlscan" {
				t.Fatalf("deduped URL = %+v, want last-write category/source/interesting", u)
			}
		}
	}
	if !found {
		t.Fatal("missing expected URL")
	}
}

func TestSaveEmailsBatch(t *testing.T) {
	db := newTestDB(t)

	records := []EmailRecord{
		{Domain: "example.com", Address: "a@example.com", Source: "hunter"},
		{Domain: "example.com", Address: "b@example.com", Source: "github"},
		{Domain: "example.com", Address: "a@example.com", Source: "skymem"},
		{Domain: "example.com", Address: "", Source: "ignore"},
	}
	if err := db.SaveEmails(records); err != nil {
		t.Fatalf("SaveEmails: %v", err)
	}

	got, err := db.GetEmailsForDomain("example.com")
	if err != nil {
		t.Fatalf("GetEmailsForDomain: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d emails, want 2", len(got))
	}
}

func TestDomainAddReturning(t *testing.T) {
	db := newTestDB(t)

	first, err := db.Domains.Add("example.com")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if first.ID == 0 || first.Domain != "example.com" || !first.Active {
		t.Fatalf("unexpected domain: %+v", first)
	}

	second, err := db.Domains.Add("example.com")
	if err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate Add IDs %d vs %d", second.ID, first.ID)
	}
}

func BenchmarkSaveURLs(b *testing.B) {
	benchmarkSaveURLs(b, true)
}

func BenchmarkSaveURLsRowByRow(b *testing.B) {
	benchmarkSaveURLs(b, false)
}

func benchmarkSaveURLs(b *testing.B, batched bool) {
	b.Helper()
	db, err := New(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	records := make([]URLRecord, 2000)
	for i := range records {
		records[i] = URLRecord{
			Domain: "example.com",
			URL:    fmt.Sprintf("https://example.com/p/%d", i),
			Source: "wayback",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range records {
			records[j].URL = fmt.Sprintf("https://example.com/%d/p/%d", i, j)
		}
		if err := db.WithTransaction(func(tx *Transaction) error {
			if batched {
				return tx.SaveURLs(records)
			}
			for _, rec := range records {
				if err := tx.SaveURL(rec.Domain, rec.URL, rec.Category, rec.Source, rec.Interesting); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func newTestDB(t *testing.T) *Database {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
