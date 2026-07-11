package scheduler

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/notifier"
	"github.com/asm-tool/asm-go/internal/parallel"
)

// JobType identifies a scheduled job.
type JobType string

const (
	JobFullScan  JobType = "full_scan"
	JobCertCheck JobType = "cert_check"
)

// ScheduledRun records a single execution of a scheduled job.
type ScheduledRun struct {
	ID        int64     `db:"id"`
	JobType   string    `db:"job_type"`
	Domain    string    `db:"domain"`
	Status    string    `db:"status"` // running, success, failed
	StartedAt time.Time `db:"started_at"`
	EndedAt   time.Time `db:"ended_at"`
	Duration  int64     `db:"duration_ms"`
	Error     string    `db:"error"`
}

// cronSchedule represents a parsed 5-field cron expression (minute hour dom month dow).
type cronSchedule struct {
	minute, hour, dom, month, dow fieldSet
	raw                           string
}

// fieldSet represents allowed values for a single cron field.
type fieldSet map[int]bool

// ParseCron parses a standard 5-field cron expression.
// Fields: minute(0-59) hour(0-23) day-of-month(1-31) month(1-12) day-of-week(0-7, 0 and 7 = Sunday).
// Supports: *, */N, N, N-M, N,M.
func ParseCron(expr string) (*cronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have 5 fields, got %d", len(fields))
	}

	minute, err := parseField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	hour, err := parseField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	dom, err := parseField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	month, err := parseField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	dow, err := parseField(fields[4], 0, 7) // 0 and 7 both = Sunday
	if err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}

	// Normalize dow: treat 7 as 0 (Sunday)
	if dow[7] {
		dow[0] = true
		delete(dow, 7)
	}

	return &cronSchedule{
		minute: minute,
		hour:   hour,
		dom:    dom,
		month:  month,
		dow:    dow,
		raw:    expr,
	}, nil
}

// Next returns the next time the schedule matches after the given time.
func (cs *cronSchedule) Next(after time.Time) time.Time {
	// Start from the next minute boundary
	t := after.Truncate(time.Minute).Add(time.Minute)

	// Brute-force search (max ~2 years of minutes)
	for i := 0; i < 1051200; i++ {
		if cs.matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return after // should never happen for valid cron
}

// matches checks if a time matches the cron schedule.
func (cs *cronSchedule) matches(t time.Time) bool {
	if !cs.minute[t.Minute()] {
		return false
	}
	if !cs.hour[t.Hour()] {
		return false
	}
	if !cs.dom[t.Day()] {
		return false
	}
	if !cs.month[int(t.Month())] {
		return false
	}
	if !cs.dow[int(t.Weekday())] {
		return false
	}
	return true
}

// parseField parses a single cron field into a set of allowed values.
func parseField(field string, min, max int) (fieldSet, error) {
	fs := make(fieldSet)

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Handle step: */N or N-M/S
		step := 1
		if idx := strings.Index(part, "/"); idx >= 0 {
			s, err := strconv.Atoi(part[idx+1:])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid step: %s", part)
			}
			step = s
			part = part[:idx]
		}

		if part == "*" {
			for v := min; v <= max; v += step {
				fs[v] = true
			}
			continue
		}

		// Handle range: N-M
		if idx := strings.Index(part, "-"); idx >= 0 {
			start, err := strconv.Atoi(strings.TrimSpace(part[:idx]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end: %s", part)
			}
			if start < min || end > max || start > end {
				return nil, fmt.Errorf("range out of bounds [%d-%d]: %s", min, max, part)
			}
			for v := start; v <= end; v += step {
				fs[v] = true
			}
			continue
		}

		// Single value
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid value: %s", part)
		}
		if v < min || v > max {
			return nil, fmt.Errorf("value out of bounds [%d-%d]: %d", min, max, v)
		}
		fs[v] = true
	}

	if len(fs) == 0 {
		return nil, fmt.Errorf("empty field")
	}
	return fs, nil
}

// Scheduler manages cron-based recurring scans.
type Scheduler struct {
	cfg    *config.Config
	db     *database.Database
	logger *log.Logger
	execute func(JobType, string) error
	mu     sync.Mutex
	jobs   []job
}

type job struct {
	name     string
	schedule *cronSchedule
	domains  []string
	jobType  JobType
}

// New creates a new Scheduler.
func New(cfg *config.Config, db *database.Database, logger *log.Logger) *Scheduler {
	s := &Scheduler{
		cfg:    cfg,
		db:     db,
		logger: logger,
	}
	s.execute = s.executeScan
	return s
}

// RegisterJobs registers all configured cron jobs.
func (s *Scheduler) RegisterJobs() error {
	domains := s.cfg.Domains
	if len(domains) == 0 {
		return fmt.Errorf("no domains configured — add domains to config.yaml under 'domains:'")
	}

	// Full scan job
	if s.cfg.Schedule.FullScan != "" {
		sched, err := ParseCron(s.cfg.Schedule.FullScan)
		if err != nil {
			return fmt.Errorf("invalid full_scan cron %q: %w", s.cfg.Schedule.FullScan, err)
		}
		s.jobs = append(s.jobs, job{
			name:     "full_scan",
			schedule: sched,
			domains:  domains,
			jobType:  JobFullScan,
		})
		s.logger.Printf("scheduled full_scan: %s (domains: %v)", s.cfg.Schedule.FullScan, domains)
	}

	// Cert check job
	if s.cfg.Schedule.CertCheck != "" {
		sched, err := ParseCron(s.cfg.Schedule.CertCheck)
		if err != nil {
			return fmt.Errorf("invalid cert_check cron %q: %w", s.cfg.Schedule.CertCheck, err)
		}
		s.jobs = append(s.jobs, job{
			name:     "cert_check",
			schedule: sched,
			domains:  domains,
			jobType:  JobCertCheck,
		})
		s.logger.Printf("scheduled cert_check: %s (domains: %v)", s.cfg.Schedule.CertCheck, domains)
	}

	return nil
}

// Start begins the scheduler. Blocks until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.Printf("scheduler started — checking every minute")

	// Log next runs
	for _, j := range s.jobs {
		next := j.schedule.Next(time.Now())
		s.logger.Printf("  %s next run: %s", j.name, next.Format(time.RFC3339))
	}

	ticker := time.NewTicker(30 * time.Second) // check every 30s to avoid missing minute boundaries
	defer ticker.Stop()

	var lastRun map[string]time.Time = make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("scheduler stopping...")
			return
		case now := <-ticker.C:
			for _, j := range s.jobs {
				// Check if this job should run at the current minute
				truncated := now.Truncate(time.Minute)
				if !j.schedule.matches(truncated) {
					continue
				}

				// Don't run the same job more than once per minute
				key := j.name + truncated.Format("200601021504")
				if _, already := lastRun[key]; already {
					continue
				}
				lastRun[key] = now

				s.logger.Printf("triggering %s at %s", j.name, now.Format("15:04:05"))
				go func(j job) {
					if err := s.runJob(j.jobType, j.domains); err != nil {
						s.logger.Printf("FAILED scheduled %s: %v", j.name, err)
					}
				}(j)
			}
		}
	}
}

// RunOnce executes a job immediately (for `asm schedule run`).
func (s *Scheduler) RunOnce(jobType JobType, domains []string) error {
	return s.runJob(jobType, domains)
}

// NextRuns returns the next N scheduled run times for display.
func (s *Scheduler) NextRuns(n int) []NextRun {
	var runs []NextRun
	for _, j := range s.jobs {
		next := j.schedule.Next(time.Now())
		runs = append(runs, NextRun{
			Job:    j.name,
			Next:   next,
			Domains: j.domains,
		})
	}
	return runs
}

type NextRun struct {
	Job     string
	Next    time.Time
	Domains []string
}

// RecentRuns returns the most recent scheduled runs from the database.
func (s *Scheduler) RecentRuns(limit int) ([]ScheduledRun, error) {
	var runs []ScheduledRun
	err := s.db.Raw().Select(&runs,
		`SELECT id, job_type, domain, status, started_at, ended_at, duration_ms, error
		 FROM scheduled_runs
		 ORDER BY started_at DESC
		 LIMIT ?`, limit)
	return runs, err
}

// runJob executes a scheduled job for all domains and reports every failure.
func (s *Scheduler) runJob(jobType JobType, domains []string) error {
	var errs []error
	for _, domain := range domains {
		if err := s.runDomain(jobType, domain); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", domain, err))
		}
	}
	return errors.Join(errs...)
}

// runDomain executes a scheduled job for a single domain.
func (s *Scheduler) runDomain(jobType JobType, domain string) error {
	started := time.Now()
	run := ScheduledRun{
		JobType:   string(jobType),
		Domain:    domain,
		Status:    "running",
		StartedAt: started,
	}

	// Record the run start
	runID, err := s.recordRun(&run)
	if err != nil {
		s.logger.Printf("ERROR recording run: %v", err)
	}

	s.logger.Printf("starting %s for %s", jobType, domain)

	// Execute the scan
	scanErr := s.execute(jobType, domain)

	// Update the run record
	ended := time.Now()
	run.EndedAt = ended
	run.Duration = ended.Sub(started).Milliseconds()
	if scanErr != nil {
		run.Status = "failed"
		run.Error = scanErr.Error()
		s.logger.Printf("FAILED %s for %s: %v (took %s)", jobType, domain, scanErr, ended.Sub(started).Round(time.Second))
	} else {
		run.Status = "success"
		s.logger.Printf("COMPLETED %s for %s (took %s)", jobType, domain, ended.Sub(started).Round(time.Second))
	}

	if err := s.updateRun(runID, &run); err != nil {
		s.logger.Printf("ERROR updating run: %v", err)
	}

	// Send notification
	s.notify(jobType, domain, &run)

	return scanErr
}

// executeScan runs the appropriate scan for the job type.
func (s *Scheduler) executeScan(jobType JobType, domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()

	runner := parallel.DefaultRunner(s.db)
	s.configureRunner(runner, jobType)

	result, err := runner.Run(ctx, domain)
	if err != nil {
		return err
	}

	// Log result summary
	s.logger.Printf("  subdomains=%d ports=%d vulns=%d",
		len(result.Subdomains), len(result.Ports), len(result.Vulnerabilities))

	return nil
}

// configureRunner sets up the runner based on job type and config.
func (s *Scheduler) configureRunner(runner *parallel.Runner, jobType JobType) {
	runner.Ports = s.cfg.ParsePorts()
	runner.InsecureSkipVerify = s.cfg.Scanning.InsecureSkipVerify
	runner.RateLimit = s.cfg.Scanning.RateLimit
	runner.NucleiRateLimit = s.cfg.Scanning.RateLimit
	runner.HunterAPIKey = s.cfg.Hunter.APIKey

	if s.cfg.Timeouts.Subfinder > 0 {
		runner.SubdomainTimeout = s.cfg.Timeouts.Subfinder
	}
	if s.cfg.Timeouts.Nmap > 0 {
		runner.PortTimeout = s.cfg.Timeouts.Nmap
	}
	if s.cfg.Timeouts.HTTP > 0 {
		runner.HTTPTimeout = s.cfg.Timeouts.HTTP
	}
	if s.cfg.Timeouts.DNS > 0 {
		runner.DNSTimeout = s.cfg.Timeouts.DNS
	}
	if s.cfg.Timeouts.Gau > 0 {
		runner.URLTimeout = s.cfg.Timeouts.Gau
	}
	if s.cfg.Timeouts.Nuclei > 0 {
		runner.NucleiTimeout = s.cfg.Timeouts.Nuclei
	}

	if s.cfg.Nuclei.BatchSize > 0 {
		runner.NucleiBulkSize = s.cfg.Nuclei.BatchSize
	}
	if s.cfg.Nuclei.Concurrency > 0 {
		runner.NucleiConcurrency = s.cfg.Nuclei.Concurrency
	}
	runner.NucleiRetries = s.cfg.Nuclei.Retries

	if s.cfg.Scanning.NucleiSeverity != "" {
		runner.NucleiSeverities = splitCSV(s.cfg.Scanning.NucleiSeverity)
	}

	// For cert_check, enable subdomains + certificates only
	if jobType == JobCertCheck {
		for k := range runner.EnabledModules {
			runner.EnabledModules[k] = false
		}
		runner.EnabledModules[parallel.ModuleSubdomains] = true
		runner.EnabledModules[parallel.ModuleCertificates] = true
	}
}

// recordRun inserts a new run record and returns its ID.
func (s *Scheduler) recordRun(run *ScheduledRun) (int64, error) {
	result, err := s.db.Raw().Exec(
		`INSERT INTO scheduled_runs (job_type, domain, status, started_at, ended_at, duration_ms, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		run.JobType, run.Domain, run.Status, run.StartedAt, run.EndedAt, run.Duration, run.Error)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// updateRun updates a run record.
func (s *Scheduler) updateRun(id int64, run *ScheduledRun) error {
	_, err := s.db.Raw().Exec(
		`UPDATE scheduled_runs SET status=?, ended_at=?, duration_ms=?, error=? WHERE id=?`,
		run.Status, run.EndedAt, run.Duration, run.Error, id)
	return err
}

// notify sends notifications for completed scans.
func (s *Scheduler) notify(jobType JobType, domain string, run *ScheduledRun) {
	n := notifier.DefaultNotifier()
	n.SMTPHost = s.cfg.Notifications.Email.SMTPHost
	n.SMTPPort = s.cfg.Notifications.Email.SMTPPort
	n.EmailFrom = s.cfg.Notifications.Email.FromAddr

	if s.cfg.Notifications.Slack.Enabled {
		n.SlackWebhook = s.cfg.Notifications.Slack.WebhookURL
	}
	if s.cfg.Notifications.Email.Enabled {
		n.EmailTo = []string{s.cfg.Notifications.Email.ToAddr}
	}

	if n.SlackWebhook == "" && len(n.EmailTo) == 0 {
		return
	}

	status := "✅"
	if run.Status == "failed" {
		status = "❌"
	}
	msg := fmt.Sprintf("%s Scheduled %s for %s — %s (took %dms)",
		status, jobType, domain, run.Status, run.Duration)
	if run.Error != "" {
		msg += fmt.Sprintf("\nError: %s", run.Error)
	}

	s.logger.Printf("notification: %s", msg)
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
