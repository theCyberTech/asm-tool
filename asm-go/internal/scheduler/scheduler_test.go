package scheduler

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/parallel"
)

func TestParseCron(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"daily at 6am", "0 6 * * *", false},
		{"every 6 hours", "0 */6 * * *", false},
		{"every minute", "* * * * *", false},
		{"range 1-5", "0 9 * * 1-5", false},
		{"multiple values", "0 9,12,18 * * *", false},
		{"step range", "*/15 * * * *", false},
		{"complex", "30 2 1,15 * 1-5", false},
		{"too few fields", "0 6 * *", true},
		{"too many fields", "0 6 * * * *", true},
		{"invalid minute", "60 6 * * *", true},
		{"invalid hour", "0 25 * * *", true},
		{"invalid step", "*/0 * * * *", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sched, err := ParseCron(tt.expr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCron(%q) expected error, got nil", tt.expr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCron(%q) unexpected error: %v", tt.expr, err)
				return
			}
			if sched == nil {
				t.Errorf("ParseCron(%q) returned nil schedule", tt.expr)
			}
		})
	}
}

func TestCronScheduleMatches(t *testing.T) {
	// "0 6 * * *" = daily at 06:00
	sched, err := ParseCron("0 6 * * *")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		time time.Time
		want bool
	}{
		{time.Date(2026, 6, 6, 6, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 6, 6, 6, 1, 0, 0, time.UTC), false},
		{time.Date(2026, 6, 6, 7, 0, 0, 0, time.UTC), false},
		{time.Date(2026, 6, 7, 6, 0, 0, 0, time.UTC), true},
	}

	for _, tt := range tests {
		got := sched.matches(tt.time)
		if got != tt.want {
			t.Errorf("matches(%s) = %v, want %v", tt.time.Format("15:04 Mon"), got, tt.want)
		}
	}
}

func TestCronScheduleNext(t *testing.T) {
	// "0 6 * * *" = daily at 06:00
	sched, err := ParseCron("0 6 * * *")
	if err != nil {
		t.Fatal(err)
	}

	// If it's 5:30, next should be 6:00 same day
	before := time.Date(2026, 6, 6, 5, 30, 0, 0, time.UTC)
	next := sched.Next(before)
	expected := time.Date(2026, 6, 6, 6, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%s) = %s, want %s", before, next, expected)
	}

	// If it's 6:30, next should be 6:00 next day
	after := time.Date(2026, 6, 6, 6, 30, 0, 0, time.UTC)
	next = sched.Next(after)
	expected = time.Date(2026, 6, 7, 6, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%s) = %s, want %s", after, next, expected)
	}

	// Every 6 hours: "0 */6 * * *"
	sched2, err := ParseCron("0 */6 * * *")
	if err != nil {
		t.Fatal(err)
	}

	at3 := time.Date(2026, 6, 6, 3, 0, 0, 0, time.UTC)
	next = sched2.Next(at3)
	expected = time.Date(2026, 6, 6, 6, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%s) = %s, want %s", at3, next, expected)
	}

	// Weekdays only: "0 9 * * 1-5"
	sched3, err := ParseCron("0 9 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}

	// Friday 10am -> next should be Monday 9am
	friday := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC) // June 5, 2026 is Friday
	next = sched3.Next(friday)
	expected = time.Date(2026, 6, 8, 9, 0, 0, 0, time.UTC) // Monday
	if !next.Equal(expected) {
		t.Errorf("Next(%s) = %s, want %s", friday, next, expected)
	}
}

func TestCronScheduleNextEveryMinute(t *testing.T) {
	sched, err := ParseCron("* * * * *")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 6, 12, 30, 30, 0, time.UTC)
	next := sched.Next(now)
	expected := time.Date(2026, 6, 6, 12, 31, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Next(%s) = %s, want %s", now, next, expected)
	}
}

func TestRunOnceReturnsScanError(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(config.Default(), db, nil, log.New(io.Discard, "", 0))
	want := errors.New("scan failed")
	s.execute = func(JobType, string) (*parallel.ScanResult, error) { return nil, want }

	err = s.RunOnce(JobFullScan, []string{"crewai.com"})
	if !errors.Is(err, want) {
		t.Fatalf("RunOnce() error = %v, want wrapped %v", err, want)
	}
}

func TestRunDomainSkipsWhenAlreadyRunning(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(config.Default(), db, nil, log.New(io.Discard, "", 0))
	started := make(chan struct{})
	release := make(chan struct{})
	var executions atomic.Int32
	s.execute = func(JobType, string) (*parallel.ScanResult, error) {
		executions.Add(1)
		close(started)
		<-release
		return &parallel.ScanResult{Domain: "crewai.com"}, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- s.runDomain(JobFullScan, "crewai.com")
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not start")
	}

	if err := s.runDomain(JobFullScan, "crewai.com"); err != nil {
		t.Fatalf("overlapping runDomain() error = %v", err)
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("execute called %d times, want 1", got)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first runDomain() error = %v", err)
	}
}

func TestNotifyPostsToSlack(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Default()
	cfg.Notifications.Slack.Enabled = true
	cfg.Notifications.Slack.WebhookURL = srv.URL

	s := New(cfg, db, nil, log.New(io.Discard, "", 0))
	s.notify(JobFullScan, "example.com", &ScheduledRun{
		Status:    "success",
		StartedAt: time.Now(),
		Duration:  10,
	}, &parallel.ScanResult{Domain: "example.com"})

	if got.Load() != 1 {
		t.Fatalf("slack webhook hits = %d, want 1", got.Load())
	}
}

func TestRunDomainRejectsOutOfScope(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(config.Default(), db, nil, log.New(io.Discard, "", 0))
	called := false
	s.execute = func(JobType, string) (*parallel.ScanResult, error) {
		called = true
		return &parallel.ScanResult{}, nil
	}

	err = s.runDomain(JobFullScan, "google.com")
	if err == nil {
		t.Fatal("runDomain accepted google.com")
	}
	if !strings.Contains(err.Error(), "restricted to crewai.com") {
		t.Fatalf("runDomain error = %q, want restricted to crewai.com", err.Error())
	}
	if called {
		t.Fatal("execute should not run for an out-of-scope domain")
	}
}
