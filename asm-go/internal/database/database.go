package database

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/001_initial.sql
var initialMigration string

//go:embed migrations/002_url_source.sql
var migration002 string

//go:embed migrations/003_findings_dedup.sql
var migration003 string

//go:embed migrations/004_snapshot_vulns.sql
var migration004 string

//go:embed migrations/005_scheduled_runs.sql
var migration005 string

//go:embed migrations/006_query_indexes.sql
var migration006 string

// Database is the main database facade
type Database struct {
	db *sqlx.DB

	// Repositories
	Domains      *DomainRepository
	Ports        *PortRepository
	Certificates *CertificateRepository
	Findings     *FindingRepository
}

type queryExecutor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Get(dest interface{}, query string, args ...interface{}) error
	Select(dest interface{}, query string, args ...interface{}) error
}

// Transaction exposes the database repositories and helper methods inside a
// single SQL transaction.
type Transaction struct {
	db queryExecutor

	Domains      *DomainRepository
	Ports        *PortRepository
	Certificates *CertificateRepository
	Findings     *FindingRepository
}

// New creates a new database connection and initializes repositories
func New(dbPath string) (*Database, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating database directory: %w", err)
		}
	}

	// Open database with WAL mode for better concurrency
	db, err := sqlx.Connect("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Set connection pool settings
	// SQLite in WAL mode supports concurrent readers; allow a few connections
	// so dashboard reads don't block behind a long-running scan persist.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	d := &Database{db: db}

	// Run migrations
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Initialize repositories
	d.Domains = &DomainRepository{db: db}
	d.Ports = &PortRepository{db: db}
	d.Certificates = &CertificateRepository{db: db}
	d.Findings = &FindingRepository{db: db}

	return d, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// WithTransaction runs fn in a transaction and rolls back if fn returns an
// error. The callback receives transaction-bound repositories and helpers.
func (d *Database) WithTransaction(fn func(*Transaction) error) (err error) {
	tx, err := d.db.Beginx()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	completed := false
	defer func() {
		if completed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = fmt.Errorf("rolling back transaction: %w", rollbackErr)
			if err != nil {
				err = errors.Join(err, rollbackErr)
			} else {
				err = rollbackErr
			}
		}
	}()

	if err = fn(newTransaction(tx)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	completed = true
	return nil
}

func newTransaction(tx *sqlx.Tx) *Transaction {
	return &Transaction{
		db:           tx,
		Domains:      &DomainRepository{db: tx},
		Ports:        &PortRepository{db: tx},
		Certificates: &CertificateRepository{db: tx},
		Findings:     &FindingRepository{db: tx},
	}
}

// migrate runs database migrations
func (d *Database) migrate() error {
	var version int
	err := d.db.Get(&version, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err != nil {
		// Table doesn't exist, run initial migration
		if _, err = d.db.Exec(initialMigration); err != nil {
			return fmt.Errorf("running initial migration: %w", err)
		}
		version = 1
	}

	if version < 2 {
		if _, err = d.db.Exec(migration002); err != nil {
			return fmt.Errorf("running migration 002: %w", err)
		}
		version = 2
	}

	if version < 3 {
		if _, err = d.db.Exec(migration003); err != nil {
			return fmt.Errorf("running migration 003: %w", err)
		}
	}

	if version < 4 {
		if _, err = d.db.Exec(migration004); err != nil {
			return fmt.Errorf("running migration 004: %w", err)
		}
	}

	if version < 5 {
		if _, err = d.db.Exec(migration005); err != nil {
			return fmt.Errorf("running migration 005: %w", err)
		}
	}

	if version < 6 {
		if _, err = d.db.Exec(migration006); err != nil {
			return fmt.Errorf("running migration 006: %w", err)
		}
	}

	return nil
}

// Stats returns database statistics
type Stats struct {
	Domains      int `db:"domain_count"`
	Subdomains   int `db:"subdomain_count"`
	Ports        int `db:"port_count"`
	Certificates int `db:"certificate_count"`
	Findings     int `db:"finding_count"`
	Takeovers    int `db:"takeover_count"`
	URLs         int `db:"url_count"`
	APIs         int `db:"api_count"`
	Emails       int `db:"email_count"`
	CloudBuckets int `db:"bucket_count"`
}

// GetStats returns counts for all tables
func (d *Database) GetStats() (*Stats, error) {
	stats := &Stats{}

	queries := []struct {
		query string
		dest  *int
	}{
		{"SELECT COUNT(*) FROM domains", &stats.Domains},
		{"SELECT COUNT(*) FROM subdomains", &stats.Subdomains},
		{"SELECT COUNT(*) FROM ports WHERE state = 'open'", &stats.Ports},
		{"SELECT COUNT(*) FROM certificates", &stats.Certificates},
		{"SELECT COUNT(*) FROM findings WHERE status = 'open'", &stats.Findings},
		{"SELECT COUNT(*) FROM takeovers WHERE status = 'open'", &stats.Takeovers},
		{"SELECT COUNT(*) FROM urls", &stats.URLs},
		{"SELECT COUNT(*) FROM apis", &stats.APIs},
		{"SELECT COUNT(*) FROM emails", &stats.Emails},
		{"SELECT COUNT(*) FROM cloud_storage WHERE status = 'open'", &stats.CloudBuckets},
	}

	var errs []string
	for _, q := range queries {
		if err := d.db.Get(q.dest, q.query); err != nil {
			// Table not existing is expected for fresh databases
			if isTableNotExistsError(err) {
				*q.dest = 0
				continue
			}
			// Log unexpected errors but continue to collect other stats
			errs = append(errs, fmt.Sprintf("query %q: %v", q.query, err))
			*q.dest = 0
		}
	}

	// Return aggregate error if any unexpected errors occurred
	if len(errs) > 0 {
		return stats, fmt.Errorf("stats query errors: %s", strings.Join(errs, "; "))
	}

	return stats, nil
}

// isTableNotExistsError checks if the error is due to a missing table
func isTableNotExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no such table") ||
		strings.Contains(errStr, "doesn't exist")
}

// FindingSeverityCounts returns counts of findings by severity
type FindingSeverityCounts struct {
	Critical int `db:"critical"`
	High     int `db:"high"`
	Medium   int `db:"medium"`
	Low      int `db:"low"`
	Info     int `db:"info"`
}

// GetFindingSeverityCounts returns finding counts grouped by severity
func (d *Database) GetFindingSeverityCounts() (*FindingSeverityCounts, error) {
	counts := &FindingSeverityCounts{}

	rows, err := d.db.Query(`
		SELECT severity, COUNT(*) as count
		FROM findings
		WHERE status = 'open'
		GROUP BY severity
	`)
	if err != nil {
		// Table not existing is expected for fresh databases
		if isTableNotExistsError(err) {
			return counts, nil
		}
		return counts, fmt.Errorf("querying finding severity counts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return counts, fmt.Errorf("scanning severity count row: %w", err)
		}
		switch severity {
		case "critical":
			counts.Critical = count
		case "high":
			counts.High = count
		case "medium":
			counts.Medium = count
		case "low":
			counts.Low = count
		case "info":
			counts.Info = count
		}
	}

	if err := rows.Err(); err != nil {
		return counts, fmt.Errorf("iterating severity counts: %w", err)
	}

	return counts, nil
}

// Domain represents a tracked domain
type Domain struct {
	ID          int64      `db:"id"`
	Domain      string     `db:"domain"`
	AddedAt     time.Time  `db:"added_at"`
	LastScanned *time.Time `db:"last_scanned"`
	Active      bool       `db:"active"`
}

// Subdomain represents a discovered subdomain
type Subdomain struct {
	ID           int64     `db:"id"`
	DomainID     int64     `db:"domain_id"`
	Subdomain    string    `db:"subdomain"`
	DiscoveredAt time.Time `db:"discovered_at"`
	LastSeen     time.Time `db:"last_seen"`
	Active       bool      `db:"active"`
}

// Port represents an open port
type Port struct {
	ID           int64     `db:"id"`
	Host         string    `db:"host"`
	Port         int       `db:"port"`
	Protocol     string    `db:"protocol"`
	Service      string    `db:"service"`
	Version      string    `db:"version"`
	Product      string    `db:"product"`
	State        string    `db:"state"`
	Banner       string    `db:"banner"`
	DiscoveredAt time.Time `db:"discovered_at"`
	LastSeen     time.Time `db:"last_seen"`
}

// Certificate represents a TLS certificate
type Certificate struct {
	ID                 int64     `db:"id"`
	Host               string    `db:"host"`
	Port               int       `db:"port"`
	Subject            string    `db:"subject"`
	Issuer             string    `db:"issuer"`
	SerialNumber       string    `db:"serial_number"`
	NotBefore          time.Time `db:"not_before"`
	NotAfter           time.Time `db:"not_after"`
	DaysUntilExpiry    int       `db:"days_until_expiry"`
	Fingerprint        string    `db:"fingerprint"`
	SAN                string    `db:"san"`
	SignatureAlgorithm string    `db:"signature_algorithm"`
	CheckedAt          time.Time `db:"checked_at"`
}

// Finding represents a vulnerability finding
type Finding struct {
	ID           int64      `db:"id"`
	TemplateID   string     `db:"template_id"`
	Name         string     `db:"name"`
	Severity     string     `db:"severity"`
	Description  string     `db:"description"`
	Host         string     `db:"host"`
	MatchedAt    string     `db:"matched_at"`
	MatcherName  string     `db:"matcher_name"`
	Evidence     string     `db:"evidence"`
	Refs         string     `db:"refs"`
	Tags         string     `db:"tags"`
	Type         string     `db:"type"`
	Status       string     `db:"status"`
	DiscoveredAt time.Time  `db:"discovered_at"`
	ResolvedAt   *time.Time `db:"resolved_at"`
}

// DomainRepository handles domain persistence
type DomainRepository struct {
	db queryExecutor
}

// Add adds a new domain
func (r *DomainRepository) Add(domain string) (*Domain, error) {
	var d Domain
	err := r.db.Get(&d, `
		INSERT INTO domains (domain) VALUES (?)
		ON CONFLICT(domain) DO UPDATE SET active = 1
		RETURNING *
	`, domain)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetByID retrieves a domain by ID
func (r *DomainRepository) GetByID(id int64) (*Domain, error) {
	var d Domain
	err := r.db.Get(&d, "SELECT * FROM domains WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetByName retrieves a domain by name
func (r *DomainRepository) GetByName(name string) (*Domain, error) {
	var d Domain
	err := r.db.Get(&d, "SELECT * FROM domains WHERE domain = ?", name)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// List returns all active domains
func (r *DomainRepository) List() ([]Domain, error) {
	var domains []Domain
	err := r.db.Select(&domains, "SELECT * FROM domains WHERE active = 1 ORDER BY domain")
	return domains, err
}

// AddSubdomain adds a subdomain to a domain
func (r *DomainRepository) AddSubdomain(domainID int64, subdomain string) error {
	return r.AddSubdomains(domainID, []string{subdomain})
}

// GetSubdomains returns all subdomains for a domain
func (r *DomainRepository) GetSubdomains(domainID int64) ([]Subdomain, error) {
	var subs []Subdomain
	err := r.db.Select(&subs, `
		SELECT * FROM subdomains WHERE domain_id = ? AND active = 1 ORDER BY subdomain
	`, domainID)
	return subs, err
}

// GetSubdomainsByDomainName returns all subdomains for a domain name
func (r *DomainRepository) GetSubdomainsByDomainName(domain string) ([]string, error) {
	var subs []string
	err := r.db.Select(&subs, `
		SELECT s.subdomain FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ? AND s.active = 1
		ORDER BY s.subdomain
	`, domain)
	return subs, err
}

// PortRepository handles port persistence
type PortRepository struct {
	db queryExecutor
}

// Add adds or updates a port
func (r *PortRepository) Add(p *Port) error {
	if p == nil {
		return nil
	}
	return r.AddAll([]Port{*p})
}

// GetByHost returns all open ports for a host
func (r *PortRepository) GetByHost(host string) ([]Port, error) {
	var ports []Port
	err := r.db.Select(&ports, `
		SELECT * FROM ports WHERE host = ? AND state = 'open' ORDER BY port
	`, host)
	return ports, err
}

// CertificateRepository handles certificate persistence
type CertificateRepository struct {
	db queryExecutor
}

// Add adds or updates a certificate
func (r *CertificateRepository) Add(c *Certificate) error {
	_, err := r.db.Exec(`
		INSERT INTO certificates (host, port, subject, issuer, serial_number, not_before, not_after,
			days_until_expiry, fingerprint, san, signature_algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, port) DO UPDATE SET
			subject = excluded.subject,
			issuer = excluded.issuer,
			serial_number = excluded.serial_number,
			not_before = excluded.not_before,
			not_after = excluded.not_after,
			days_until_expiry = excluded.days_until_expiry,
			fingerprint = excluded.fingerprint,
			san = excluded.san,
			signature_algorithm = excluded.signature_algorithm,
			checked_at = CURRENT_TIMESTAMP
	`, c.Host, c.Port, c.Subject, c.Issuer, c.SerialNumber, c.NotBefore, c.NotAfter,
		c.DaysUntilExpiry, c.Fingerprint, c.SAN, c.SignatureAlgorithm)
	return err
}

// GetByHost returns the certificate for a host
func (r *CertificateRepository) GetByHost(host string, port int) (*Certificate, error) {
	var cert Certificate
	err := r.db.Get(&cert, "SELECT * FROM certificates WHERE host = ? AND port = ?", host, port)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// GetExpiring returns certificates expiring within the given days
func (r *CertificateRepository) GetExpiring(days int) ([]Certificate, error) {
	var certs []Certificate
	err := r.db.Select(&certs, `
		SELECT * FROM certificates
		WHERE days_until_expiry <= ? AND days_until_expiry >= 0
		ORDER BY days_until_expiry
	`, days)
	return certs, err
}

// FindingRepository handles finding persistence
type FindingRepository struct {
	db queryExecutor
}

// Add adds a new finding or updates an existing one for the same template+host
func (r *FindingRepository) Add(f *Finding) error {
	_, err := r.db.Exec(`
		INSERT INTO findings (template_id, name, severity, description, host, matched_at,
			matcher_name, evidence, refs, tags, type, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(template_id, host) DO UPDATE SET
			name = excluded.name,
			severity = excluded.severity,
			description = excluded.description,
			matched_at = excluded.matched_at,
			matcher_name = excluded.matcher_name,
			evidence = excluded.evidence,
			refs = excluded.refs,
			tags = excluded.tags,
			type = excluded.type,
			status = 'open',
			discovered_at = CURRENT_TIMESTAMP,
			resolved_at = NULL
	`, f.TemplateID, f.Name, f.Severity, f.Description, f.Host, f.MatchedAt,
		f.MatcherName, f.Evidence, f.Refs, f.Tags, f.Type, f.Status)
	return err
}

// GetByHost returns all open findings for a host
func (r *FindingRepository) GetByHost(host string) ([]Finding, error) {
	var findings []Finding
	err := r.db.Select(&findings, `
		SELECT * FROM findings WHERE host = ? AND status = 'open' ORDER BY severity, name
	`, host)
	return findings, err
}

// GetBySeverity returns all open findings of a given severity
func (r *FindingRepository) GetBySeverity(severity string) ([]Finding, error) {
	var findings []Finding
	err := r.db.Select(&findings, `
		SELECT * FROM findings WHERE severity = ? AND status = 'open' ORDER BY discovered_at DESC
	`, severity)
	return findings, err
}

// Resolve marks a finding as resolved
func (r *FindingRepository) Resolve(id int64) error {
	_, err := r.db.Exec(`
		UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE id = ?
	`, id)
	return err
}

// Exec executes a raw SQL query (for migrations and advanced use)
func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

// Raw returns the underlying sqlx.DB for direct queries.
func (d *Database) Raw() *sqlx.DB {
	return d.db
}

// GetLatestDNSRecord returns the most recently stored DNS result for a domain.
// Returns nil, nil if no record exists yet.
func (d *Database) GetLatestDNSRecord(domain string) (*DNSRecord, error) {
	return getLatestDNSRecord(d.db, domain)
}

// GetLatestDNSRecord returns the most recently stored DNS result in this transaction.
func (tx *Transaction) GetLatestDNSRecord(domain string) (*DNSRecord, error) {
	return getLatestDNSRecord(tx.db, domain)
}

func getLatestDNSRecord(db queryExecutor, domain string) (*DNSRecord, error) {
	var rec DNSRecord
	err := db.Get(&rec, `SELECT * FROM dns_records WHERE domain = ?`, domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if isTableNotExistsError(err) {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

// SaveChangeEvent records a detected change in the change_events table.
func (d *Database) SaveChangeEvent(domain, changeType, severity, description, oldValue, newValue string) error {
	return saveChangeEvent(d.db, domain, changeType, severity, description, oldValue, newValue)
}

// SaveChangeEvent records a detected change in this transaction.
func (tx *Transaction) SaveChangeEvent(domain, changeType, severity, description, oldValue, newValue string) error {
	return saveChangeEvent(tx.db, domain, changeType, severity, description, oldValue, newValue)
}

func saveChangeEvent(db queryExecutor, domain, changeType, severity, description, oldValue, newValue string) error {
	// Build a collision-resistant event ID: domain-type-random(8 bytes)-nanos
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	eventID := fmt.Sprintf("%s-%s-%s-%d", domain, changeType, hex.EncodeToString(rnd[:]), time.Now().UnixNano())
	_, err := db.Exec(`
		INSERT INTO change_events (event_id, domain, change_type, severity, description, old_value, new_value)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, eventID, domain, changeType, severity, description, oldValue, newValue)
	return err
}

// ChangeEvent represents a DNS change event
type ChangeEvent struct {
	ID          int64     `db:"id"`
	EventID     string    `db:"event_id"`
	Domain      string    `db:"domain"`
	ChangeType  string    `db:"change_type"`
	Severity    string    `db:"severity"`
	Description string    `db:"description"`
	OldValue    string    `db:"old_value"`
	NewValue    string    `db:"new_value"`
	Timestamp   time.Time `db:"timestamp"`
}

// GetChangeEvents returns recent change events, optionally filtered by domain.
// Pass empty string for domain to get all events. Limit <= 0 defaults to 100.
func (d *Database) GetChangeEvents(domain string, limit int) ([]ChangeEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows []ChangeEvent
		err  error
	)
	if domain != "" {
		err = d.db.Select(&rows, `
			SELECT * FROM change_events WHERE domain = ?
			ORDER BY timestamp DESC LIMIT ?`, domain, limit)
	} else {
		err = d.db.Select(&rows, `
			SELECT * FROM change_events
			ORDER BY timestamp DESC LIMIT ?`, limit)
	}
	if err != nil {
		if isTableNotExistsError(err) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// Takeover represents a subdomain takeover finding
type Takeover struct {
	ID            int64      `db:"id"`
	Subdomain     string     `db:"subdomain"`
	CNAME         string     `db:"cname"`
	Service       string     `db:"service"`
	TakeoverType  string     `db:"takeover_type"`
	Confidence    string     `db:"confidence"`
	Evidence      string     `db:"evidence"`
	Documentation string     `db:"documentation"`
	Status        string     `db:"status"`
	DiscoveredAt  time.Time  `db:"discovered_at"`
	ResolvedAt    *time.Time `db:"resolved_at"`
}

// URL represents a discovered URL
type URL struct {
	ID           int64          `db:"id"`
	URL          string         `db:"url"`
	Domain       string         `db:"domain"`
	Category     sql.NullString `db:"category"`
	Interesting  int            `db:"interesting"`
	Source       string         `db:"source"`
	DiscoveredAt time.Time      `db:"discovered_at"`
}

// API represents a discovered API endpoint
type API struct {
	ID           int64          `db:"id"`
	URL          string         `db:"url"`
	Type         sql.NullString `db:"api_type"`
	Title        sql.NullString `db:"title"`
	Version      sql.NullString `db:"version"`
	DiscoveredAt time.Time      `db:"discovered_at"`
}

// Email represents a discovered email address
type Email struct {
	ID           int64     `db:"id"`
	Address      string    `db:"email"`
	Domain       string    `db:"domain"`
	Source       string    `db:"source"`
	DiscoveredAt time.Time `db:"discovered_at"`
}

// CloudStorage represents a cloud storage bucket
type CloudStorage struct {
	ID           int64          `db:"id"`
	Provider     string         `db:"provider"`
	BucketName   string         `db:"bucket_name"`
	URL          string         `db:"url"`
	Domain       string         `db:"domain"`
	Source       sql.NullString `db:"source"`
	AccessLevel  string         `db:"access_level"`
	Severity     string         `db:"severity"`
	Evidence     string         `db:"evidence"`
	Status       string         `db:"status"`
	DiscoveredAt time.Time      `db:"discovered_at"`
}

// GetCertificatesForDomain returns all certificates for hosts matching a domain
func (d *Database) GetCertificatesForDomain(domain string) ([]Certificate, error) {
	var certs []Certificate
	err := d.db.Select(&certs, `
		SELECT
			id, host, port,
			COALESCE(subject, '') AS subject,
			COALESCE(issuer, '') AS issuer,
			COALESCE(serial_number, '') AS serial_number,
			not_before,
			not_after,
			COALESCE(days_until_expiry, 0) AS days_until_expiry,
			COALESCE(fingerprint, '') AS fingerprint,
			COALESCE(san, '') AS san,
			COALESCE(signature_algorithm, '') AS signature_algorithm,
			checked_at
		FROM certificates
		WHERE host = ? OR host LIKE ?
		ORDER BY days_until_expiry
	`, domain, "%."+domain)
	return certs, err
}

// GetTakeoversForDomain returns all takeover findings for a domain
func (d *Database) GetTakeoversForDomain(domain string) ([]Takeover, error) {
	var takeovers []Takeover
	err := d.db.Select(&takeovers, `
		SELECT * FROM takeovers
		WHERE (subdomain = ? OR subdomain LIKE ?) AND status = 'open'
		ORDER BY subdomain
	`, domain, "%."+domain)
	if err != nil && isTableNotExistsError(err) {
		return []Takeover{}, nil
	}
	return takeovers, err
}

// GetURLsForDomain returns all URLs for a domain
func (d *Database) GetURLsForDomain(domain string) ([]URL, error) {
	return d.GetURLsForDomainLimit(domain, 0)
}

// GetURLsForDomainLimit returns URLs for a domain, optionally capped by limit (0 = no cap).
func (d *Database) GetURLsForDomainLimit(domain string, limit int) ([]URL, error) {
	var urls []URL
	query := `
		SELECT * FROM urls
		WHERE domain = ? OR domain LIKE ?
		ORDER BY url
	`
	args := []interface{}{domain, "%." + domain}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	err := d.db.Select(&urls, query, args...)
	return urls, err
}

// GetAPIsForDomain returns all APIs for a domain
func (d *Database) GetAPIsForDomain(domain string) ([]API, error) {
	var apis []API
	err := d.db.Select(&apis, `
		SELECT id, url, api_type, title, version, discovered_at FROM apis
		WHERE url LIKE ?
		ORDER BY url
	`, "%"+domain+"%")
	return apis, err
}

// GetEmailsForDomain returns all emails for a domain
func (d *Database) GetEmailsForDomain(domain string) ([]Email, error) {
	var emails []Email
	err := d.db.Select(&emails, `
		SELECT id, email, domain, source, discovered_at FROM emails
		WHERE domain = ?
		ORDER BY email
	`, domain)
	return emails, err
}

// GetCloudStorageForDomain returns all cloud storage buckets for a domain
func (d *Database) GetCloudStorageForDomain(domain string) ([]CloudStorage, error) {
	var buckets []CloudStorage
	err := d.db.Select(&buckets, `
		SELECT * FROM cloud_storage
		WHERE domain = ?
		ORDER BY severity DESC, bucket_name
	`, domain)
	return buckets, err
}

// DomainWithStats represents a domain with aggregate statistics
type DomainWithStats struct {
	ID             int64      `db:"id"`
	Domain         string     `db:"domain"`
	AddedAt        time.Time  `db:"added_at"`
	LastScanned    *time.Time `db:"last_scanned"`
	Active         bool       `db:"active"`
	SubdomainCount int        `db:"subdomain_count"`
	PortCount      int        `db:"port_count"`
	CriticalCount  int        `db:"critical_count"`
	HighCount      int        `db:"high_count"`
}

// GetDomainsWithStats returns all active domains with their aggregate statistics
func (d *Database) GetDomainsWithStats() ([]DomainWithStats, error) {
	var domains []DomainWithStats

	err := d.db.Select(&domains, `
		SELECT
			d.id,
			d.domain,
			d.added_at,
			d.last_scanned,
			d.active,
			COALESCE(sub.subdomain_count, 0) as subdomain_count,
			COALESCE(p.port_count, 0) as port_count,
			COALESCE(f.critical_count, 0) as critical_count,
			COALESCE(f.high_count, 0) as high_count
		FROM domains d
		LEFT JOIN (
			SELECT domain_id, COUNT(*) as subdomain_count
			FROM subdomains
			WHERE active = 1
			GROUP BY domain_id
		) sub ON sub.domain_id = d.id
		LEFT JOIN (
			SELECT
				d2.id as domain_id,
				COUNT(*) as port_count
			FROM domains d2
			JOIN subdomains s ON s.domain_id = d2.id
			JOIN ports pt ON pt.host = s.subdomain AND pt.state = 'open'
			GROUP BY d2.id
		) p ON p.domain_id = d.id
		LEFT JOIN (
			SELECT
				d3.id as domain_id,
				SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
				SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high_count
			FROM domains d3
			JOIN findings f ON f.host LIKE '%' || d3.domain AND f.status = 'open'
			GROUP BY d3.id
		) f ON f.domain_id = d.id
		WHERE d.active = 1
		ORDER BY d.domain
	`)

	if err != nil {
		if isTableNotExistsError(err) {
			return []DomainWithStats{}, nil
		}
		return nil, fmt.Errorf("querying domains with stats: %w", err)
	}

	return domains, nil
}

// GetVulnerabilitiesForDomain returns all vulnerabilities for a domain
func (d *Database) GetVulnerabilitiesForDomain(domain string) ([]Finding, error) {
	var findings []Finding
	err := d.db.Select(&findings, `
		SELECT * FROM findings
		WHERE (host = ? OR host LIKE ?) AND status = 'open'
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			name
	`, domain, "%."+domain)
	return findings, err
}

// Technology represents a technology fingerprint result
type Technology struct {
	ID            int64     `db:"id"`
	Host          string    `db:"host"`
	StatusCode    int       `db:"status_code"`
	Title         string    `db:"title"`
	Server        string    `db:"server"`
	Technologies  string    `db:"technologies"`
	Headers       string    `db:"headers"`
	ContentLength int       `db:"content_length"`
	RedirectURL   string    `db:"redirect_url"`
	CheckedAt     time.Time `db:"checked_at"`
}

// DNSRecord represents stored DNS records
type DNSRecord struct {
	ID        int64     `db:"id"`
	Domain    string    `db:"domain"`
	Records   string    `db:"records"`
	CheckedAt time.Time `db:"checked_at"`
}

// GetTechnologiesForDomain returns all technology fingerprints for a domain
func (d *Database) GetTechnologiesForDomain(domain string) ([]Technology, error) {
	var techs []Technology
	err := d.db.Select(&techs, `
		SELECT
			id, host,
			COALESCE(status_code, 0) AS status_code,
			COALESCE(title, '') AS title,
			COALESCE(server, '') AS server,
			COALESCE(technologies, '') AS technologies,
			COALESCE(headers, '') AS headers,
			COALESCE(content_length, 0) AS content_length,
			COALESCE(redirect_url, '') AS redirect_url,
			checked_at
		FROM technologies
		WHERE host = ? OR host LIKE ?
		ORDER BY host
	`, domain, "%."+domain)
	if err != nil && isTableNotExistsError(err) {
		return []Technology{}, nil
	}
	return techs, err
}

// GetDNSRecordsForDomain returns DNS records for a domain
func (d *Database) GetDNSRecordsForDomain(domain string) ([]DNSRecord, error) {
	var records []DNSRecord
	err := d.db.Select(&records, `
		SELECT
			id, domain,
			COALESCE(records, '') AS records,
			checked_at
		FROM dns_records
		WHERE domain = ? OR domain LIKE ?
		ORDER BY domain
	`, domain, "%."+domain)
	if err != nil && isTableNotExistsError(err) {
		return []DNSRecord{}, nil
	}
	return records, err
}

// GetPortsForDomain returns all open ports for hosts under a domain
func (d *Database) GetPortsForDomain(domain string) ([]Port, error) {
	var ports []Port
	err := d.db.Select(&ports, `
		SELECT
			id, host, port,
			COALESCE(protocol, 'tcp') AS protocol,
			COALESCE(service, '') AS service,
			COALESCE(version, '') AS version,
			COALESCE(product, '') AS product,
			COALESCE(state, 'open') AS state,
			COALESCE(banner, '') AS banner,
			discovered_at,
			last_seen
		FROM ports
		WHERE (host = ? OR host LIKE ?) AND state = 'open'
		ORDER BY host, port
	`, domain, "%."+domain)
	if err != nil && isTableNotExistsError(err) {
		return []Port{}, nil
	}
	return ports, err
}

// GetSubdomainsForDomain returns all subdomains for a domain name
func (d *Database) GetSubdomainsForDomain(domain string) ([]Subdomain, error) {
	var subs []Subdomain
	err := d.db.Select(&subs, `
		SELECT s.* FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ? AND s.active = 1
		ORDER BY s.subdomain
	`, domain)
	if err != nil && isTableNotExistsError(err) {
		return []Subdomain{}, nil
	}
	return subs, err
}

// DomainDetailStats holds counts for a domain detail view
type DomainDetailStats struct {
	SubdomainCount   int `db:"subdomain_count"`
	PortCount        int `db:"port_count"`
	CertificateCount int `db:"certificate_count"`
	TechnologyCount  int `db:"technology_count"`
	DNSRecordCount   int `db:"dns_record_count"`
	VulnCount        int `db:"vuln_count"`
	URLCount         int `db:"url_count"`
	APICount         int `db:"api_count"`
	EmailCount       int `db:"email_count"`
	CloudCount       int `db:"cloud_count"`
	TakeoverCount    int `db:"takeover_count"`
}

// UpdateDomainLastScanned updates the last_scanned timestamp for a domain
func (d *Database) UpdateDomainLastScanned(domain string) error {
	return updateDomainLastScanned(d.db, domain)
}

// UpdateDomainLastScanned updates last_scanned in this transaction.
func (tx *Transaction) UpdateDomainLastScanned(domain string) error {
	return updateDomainLastScanned(tx.db, domain)
}

func updateDomainLastScanned(db queryExecutor, domain string) error {
	_, err := db.Exec(`
		UPDATE domains SET last_scanned = CURRENT_TIMESTAMP WHERE domain = ?
	`, domain)
	return err
}

// SaveTechnology upserts a technology fingerprint result for a host
func (d *Database) SaveTechnology(host string, statusCode int, title, server, techJSON, headersJSON string, contentLength int64, redirectURL string) error {
	return saveTechnology(d.db, host, statusCode, title, server, techJSON, headersJSON, contentLength, redirectURL)
}

// SaveTechnology upserts a technology fingerprint result in this transaction.
func (tx *Transaction) SaveTechnology(host string, statusCode int, title, server, techJSON, headersJSON string, contentLength int64, redirectURL string) error {
	return saveTechnology(tx.db, host, statusCode, title, server, techJSON, headersJSON, contentLength, redirectURL)
}

func saveTechnology(db queryExecutor, host string, statusCode int, title, server, techJSON, headersJSON string, contentLength int64, redirectURL string) error {
	_, err := db.Exec(`
		INSERT INTO technologies (host, status_code, title, server, technologies, headers, content_length, redirect_url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET
			status_code = excluded.status_code,
			title = excluded.title,
			server = excluded.server,
			technologies = excluded.technologies,
			headers = excluded.headers,
			content_length = excluded.content_length,
			redirect_url = excluded.redirect_url,
			checked_at = CURRENT_TIMESTAMP
	`, host, statusCode, title, server, techJSON, headersJSON, contentLength, redirectURL)
	return err
}

// SaveDNSRecords upserts DNS records for a domain
func (d *Database) SaveDNSRecords(domain, recordsJSON string) error {
	return saveDNSRecords(d.db, domain, recordsJSON)
}

// SaveDNSRecords upserts DNS records in this transaction.
func (tx *Transaction) SaveDNSRecords(domain, recordsJSON string) error {
	return saveDNSRecords(tx.db, domain, recordsJSON)
}

func saveDNSRecords(db queryExecutor, domain, recordsJSON string) error {
	_, err := db.Exec(`
		INSERT INTO dns_records (domain, records)
		VALUES (?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			records = excluded.records,
			checked_at = CURRENT_TIMESTAMP
	`, domain, recordsJSON)
	return err
}

// SaveTakeover upserts a subdomain takeover finding
func (d *Database) SaveTakeover(subdomain, cname, service, confidence, evidence string) error {
	return saveTakeover(d.db, subdomain, cname, service, confidence, evidence)
}

// SaveTakeover upserts a subdomain takeover finding in this transaction.
func (tx *Transaction) SaveTakeover(subdomain, cname, service, confidence, evidence string) error {
	return saveTakeover(tx.db, subdomain, cname, service, confidence, evidence)
}

func saveTakeover(db queryExecutor, subdomain, cname, service, confidence, evidence string) error {
	_, err := db.Exec(`
		INSERT INTO takeovers (subdomain, cname, service, confidence, evidence)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(subdomain, service) DO UPDATE SET
			cname = excluded.cname,
			confidence = excluded.confidence,
			evidence = excluded.evidence
	`, subdomain, cname, service, confidence, evidence)
	return err
}

// SaveURL upserts a discovered URL
func (d *Database) SaveURL(domain, url, category, source string, interesting int) error {
	return saveURL(d.db, domain, url, category, source, interesting)
}

// SaveURL upserts a discovered URL in this transaction.
func (tx *Transaction) SaveURL(domain, url, category, source string, interesting int) error {
	return saveURL(tx.db, domain, url, category, source, interesting)
}

func saveURL(db queryExecutor, domain, url, category, source string, interesting int) error {
	return saveURLs(db, []URLRecord{{
		Domain:      domain,
		URL:         url,
		Category:    category,
		Source:      source,
		Interesting: interesting,
	}})
}

// SaveAPI upserts a discovered API endpoint
func (d *Database) SaveAPI(url, apiType, title, version string, endpointsCount int, endpointsJSON string) error {
	return saveAPI(d.db, url, apiType, title, version, endpointsCount, endpointsJSON)
}

// SaveAPI upserts a discovered API endpoint in this transaction.
func (tx *Transaction) SaveAPI(url, apiType, title, version string, endpointsCount int, endpointsJSON string) error {
	return saveAPI(tx.db, url, apiType, title, version, endpointsCount, endpointsJSON)
}

func saveAPI(db queryExecutor, url, apiType, title, version string, endpointsCount int, endpointsJSON string) error {
	_, err := db.Exec(`
		INSERT INTO apis (url, api_type, title, version, endpoints_count, endpoints)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			api_type = excluded.api_type,
			title = excluded.title,
			version = excluded.version,
			endpoints_count = excluded.endpoints_count,
			endpoints = excluded.endpoints
	`, url, apiType, title, version, endpointsCount, endpointsJSON)
	return err
}

// SaveEmail upserts a discovered email address
func (d *Database) SaveEmail(domain, email, source string) error {
	return saveEmail(d.db, domain, email, source)
}

// SaveEmail upserts a discovered email address in this transaction.
func (tx *Transaction) SaveEmail(domain, email, source string) error {
	return saveEmail(tx.db, domain, email, source)
}

func saveEmail(db queryExecutor, domain, email, source string) error {
	return saveEmails(db, []EmailRecord{{
		Domain:  domain,
		Address: email,
		Source:  source,
	}})
}

// SaveCloudBucket upserts a cloud storage bucket
func (d *Database) SaveCloudBucket(provider, bucketName, url, domain, accessLevel, severity, evidence string) error {
	return saveCloudBucket(d.db, provider, bucketName, url, domain, accessLevel, severity, evidence)
}

// SaveCloudBucket upserts a cloud storage bucket in this transaction.
func (tx *Transaction) SaveCloudBucket(provider, bucketName, url, domain, accessLevel, severity, evidence string) error {
	return saveCloudBucket(tx.db, provider, bucketName, url, domain, accessLevel, severity, evidence)
}

func saveCloudBucket(db queryExecutor, provider, bucketName, url, domain, accessLevel, severity, evidence string) error {
	_, err := db.Exec(`
		INSERT INTO cloud_storage (provider, bucket_name, url, domain, access_level, severity, evidence)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			access_level = excluded.access_level,
			severity = excluded.severity,
			evidence = excluded.evidence
	`, provider, bucketName, url, domain, accessLevel, severity, evidence)
	return err
}

// GetDomainDetailStats returns aggregate counts for a specific domain
func (d *Database) GetDomainDetailStats(domain string) (*DomainDetailStats, error) {
	stats := &DomainDetailStats{}
	hostSuffix := "%." + domain
	urlNeedle := "%" + domain + "%"

	err := d.db.Get(stats, `
		SELECT
			(SELECT COUNT(*) FROM subdomains s
			 JOIN domains d ON s.domain_id = d.id
			 WHERE d.domain = ? AND s.active = 1) AS subdomain_count,
			(SELECT COUNT(*) FROM ports
			 WHERE (host = ? OR host LIKE ?) AND state = 'open') AS port_count,
			(SELECT COUNT(*) FROM certificates
			 WHERE host = ? OR host LIKE ?) AS certificate_count,
			(SELECT COUNT(*) FROM technologies
			 WHERE host = ? OR host LIKE ?) AS technology_count,
			(SELECT COUNT(*) FROM dns_records
			 WHERE domain = ? OR domain LIKE ?) AS dns_record_count,
			(SELECT COUNT(*) FROM findings
			 WHERE (host = ? OR host LIKE ?) AND status = 'open') AS vuln_count,
			(SELECT COUNT(*) FROM urls
			 WHERE domain = ? OR domain LIKE ?) AS url_count,
			(SELECT COUNT(*) FROM apis
			 WHERE url LIKE ?) AS api_count,
			(SELECT COUNT(*) FROM emails
			 WHERE domain = ?) AS email_count,
			(SELECT COUNT(*) FROM cloud_storage
			 WHERE domain = ?) AS cloud_count,
			(SELECT COUNT(*) FROM takeovers
			 WHERE (subdomain = ? OR subdomain LIKE ?) AND status = 'open') AS takeover_count
	`, domain,
		domain, hostSuffix,
		domain, hostSuffix,
		domain, hostSuffix,
		domain, hostSuffix,
		domain, hostSuffix,
		domain, hostSuffix,
		urlNeedle,
		domain,
		domain,
		domain, hostSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to load domain detail stats: %w", err)
	}
	return stats, nil
}

// ── Global (cross-domain) list queries ──────────────────────────────────────

func (d *Database) GetAllSubdomains() ([]Subdomain, error) {
	var rows []Subdomain
	err := d.db.Select(&rows, `SELECT s.* FROM subdomains s WHERE s.active = 1 ORDER BY s.subdomain`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllPorts() ([]Port, error) {
	var rows []Port
	err := d.db.Select(&rows, `SELECT * FROM ports WHERE state = 'open' ORDER BY host, port`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllCertificates() ([]Certificate, error) {
	var rows []Certificate
	err := d.db.Select(&rows, `SELECT * FROM certificates ORDER BY days_until_expiry`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllURLs() ([]URL, error) {
	var rows []URL
	err := d.db.Select(&rows, `SELECT * FROM urls ORDER BY url`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllAPIs() ([]API, error) {
	var rows []API
	err := d.db.Select(&rows, `SELECT id, url, api_type, title, version, discovered_at FROM apis ORDER BY url`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllEmails() ([]Email, error) {
	var rows []Email
	err := d.db.Select(&rows, `SELECT id, email, domain, source, discovered_at FROM emails ORDER BY domain, email`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllCloudStorage() ([]CloudStorage, error) {
	var rows []CloudStorage
	err := d.db.Select(&rows, `SELECT * FROM cloud_storage ORDER BY severity DESC, bucket_name`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllFindings() ([]Finding, error) {
	var rows []Finding
	err := d.db.Select(&rows, `
		SELECT * FROM findings WHERE status = 'open'
		ORDER BY CASE severity
			WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
		END, name`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

func (d *Database) GetAllTakeovers() ([]Takeover, error) {
	var rows []Takeover
	err := d.db.Select(&rows, `SELECT * FROM takeovers WHERE status = 'open' ORDER BY subdomain`)
	if err != nil && isTableNotExistsError(err) {
		return nil, nil
	}
	return rows, err
}

// Snapshot represents a point-in-time capture of domain scan state.
type Snapshot struct {
	ID               int64     `db:"id"`
	SnapshotID       string    `db:"snapshot_id"`
	Domain           string    `db:"domain"`
	ScanType         string    `db:"scan_type"`
	Timestamp        time.Time `db:"timestamp"`
	SubdomainCount   int       `db:"subdomain_count"`
	PortCount        int       `db:"port_count"`
	CertificateCount int       `db:"certificate_count"`
	FindingCounts    string    `db:"finding_counts"`
	RiskScore        int       `db:"risk_score"`
	Subdomains       string    `db:"subdomains"`
	Ports            string    `db:"ports"`
	Certificates     string    `db:"certificates"`
	Vulnerabilities  string    `db:"vulnerabilities"`
}

// SaveSnapshot stores a point-in-time snapshot of a domain's scan state.
// JSON strings should be pre-encoded by the caller.
func (d *Database) SaveSnapshot(domain, scanType string, subdomainCount, portCount, certCount, riskScore int, findingCounts, subdomainsJSON, portsJSON, certsJSON, vulnsJSON string) error {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	snapshotID := fmt.Sprintf("snap-%s-%s-%d", domain, hex.EncodeToString(rnd[:]), time.Now().UnixNano())

	_, err := d.db.Exec(`
		INSERT INTO scan_snapshots
			(snapshot_id, domain, scan_type, subdomain_count, port_count, certificate_count,
			 finding_counts, risk_score, subdomains, ports, certificates, vulnerabilities)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, snapshotID, domain, scanType, subdomainCount, portCount, certCount,
		findingCounts, riskScore, subdomainsJSON, portsJSON, certsJSON, vulnsJSON)
	return err
}

// GetLatestSnapshots returns the N most recent snapshots for a domain,
// ordered newest-first.
func (d *Database) GetLatestSnapshots(domain string, limit int) ([]Snapshot, error) {
	if limit <= 0 {
		limit = 2
	}
	var snapshots []Snapshot
	err := d.db.Select(&snapshots, `
		SELECT * FROM scan_snapshots
		WHERE domain = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`, domain, limit)
	if err != nil {
		if isTableNotExistsError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying snapshots for %q: %w", domain, err)
	}
	return snapshots, nil
}
