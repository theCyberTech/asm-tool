package database

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/001_initial.sql
var initialMigration string

// Database is the main database facade
type Database struct {
	db *sqlx.DB

	// Repositories
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
	db.SetMaxOpenConns(1) // SQLite only supports one writer
	db.SetMaxIdleConns(1)
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

// migrate runs database migrations
func (d *Database) migrate() error {
	// Check current version
	var version int
	err := d.db.Get(&version, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err != nil {
		// Table doesn't exist, run initial migration
		_, err = d.db.Exec(initialMigration)
		if err != nil {
			return fmt.Errorf("running initial migration: %w", err)
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

	for _, q := range queries {
		if err := d.db.Get(q.dest, q.query); err != nil {
			// Table might not exist yet, default to 0
			*q.dest = 0
		}
	}

	return stats, nil
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
		return counts, nil // Return empty counts if query fails
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			continue
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
	db *sqlx.DB
}

// Add adds a new domain
func (r *DomainRepository) Add(domain string) (*Domain, error) {
	_, err := r.db.Exec(`
		INSERT INTO domains (domain) VALUES (?)
		ON CONFLICT(domain) DO UPDATE SET active = 1
	`, domain)
	if err != nil {
		return nil, err
	}

	// ON CONFLICT doesn't return LastInsertId, so fetch by name
	return r.GetByName(domain)
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
	_, err := r.db.Exec(`
		INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)
		ON CONFLICT(domain_id, subdomain) DO UPDATE SET last_seen = CURRENT_TIMESTAMP, active = 1
	`, domainID, subdomain)
	return err
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
	db *sqlx.DB
}

// Add adds or updates a port
func (r *PortRepository) Add(p *Port) error {
	_, err := r.db.Exec(`
		INSERT INTO ports (host, port, protocol, service, version, product, state, banner)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, port, protocol) DO UPDATE SET
			service = excluded.service,
			version = excluded.version,
			product = excluded.product,
			state = excluded.state,
			banner = excluded.banner,
			last_seen = CURRENT_TIMESTAMP
	`, p.Host, p.Port, p.Protocol, p.Service, p.Version, p.Product, p.State, p.Banner)
	return err
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
	db *sqlx.DB
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
	db *sqlx.DB
}

// Add adds a new finding
func (r *FindingRepository) Add(f *Finding) error {
	_, err := r.db.Exec(`
		INSERT INTO findings (template_id, name, severity, description, host, matched_at,
			matcher_name, evidence, refs, tags, type, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

// Takeover represents a subdomain takeover finding
type Takeover struct {
	ID         int64     `db:"id"`
	Host       string    `db:"host"`
	Vulnerable bool      `db:"vulnerable"`
	Service    string    `db:"service"`
	Confidence string    `db:"confidence"`
	Evidence   string    `db:"evidence"`
	Status     string    `db:"status"`
	CheckedAt  time.Time `db:"checked_at"`
}

// URL represents a discovered URL
type URL struct {
	ID           int64          `db:"id"`
	URL          string         `db:"url"`
	Domain       string         `db:"domain"`
	Category     sql.NullString `db:"category"`
	Interesting  int            `db:"interesting"`
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
	ID          int64     `db:"id"`
	Provider    string    `db:"provider"`
	BucketName  string    `db:"bucket_name"`
	URL         string    `db:"url"`
	Domain      string    `db:"domain"`
	AccessLevel string    `db:"access_level"`
	Severity    string    `db:"severity"`
	Evidence    string    `db:"evidence"`
	Status      string    `db:"status"`
	CheckedAt   time.Time `db:"checked_at"`
}

// GetCertificatesForDomain returns all certificates for hosts matching a domain
func (d *Database) GetCertificatesForDomain(domain string) ([]Certificate, error) {
	var certs []Certificate
	err := d.db.Select(&certs, `
		SELECT * FROM certificates
		WHERE host LIKE ? OR host = ?
		ORDER BY days_until_expiry
	`, "%"+domain, domain)
	return certs, err
}

// GetTakeoversForDomain returns all takeover findings for a domain
func (d *Database) GetTakeoversForDomain(domain string) ([]Takeover, error) {
	var takeovers []Takeover
	err := d.db.Select(&takeovers, `
		SELECT * FROM takeovers
		WHERE host LIKE ? AND status = 'open'
		ORDER BY host
	`, "%"+domain)
	return takeovers, err
}

// GetURLsForDomain returns all URLs for a domain
func (d *Database) GetURLsForDomain(domain string) ([]URL, error) {
	var urls []URL
	err := d.db.Select(&urls, `
		SELECT * FROM urls
		WHERE domain = ? OR domain LIKE ?
		ORDER BY url
	`, domain, "%."+domain)
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

// GetVulnerabilitiesForDomain returns all vulnerabilities for a domain
func (d *Database) GetVulnerabilitiesForDomain(domain string) ([]Finding, error) {
	var findings []Finding
	err := d.db.Select(&findings, `
		SELECT * FROM findings
		WHERE host LIKE ? AND status = 'open'
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			name
	`, "%"+domain)
	return findings, err
}
