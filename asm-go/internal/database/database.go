package database

import (
	"database/sql"
	_ "embed"
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

// GetLatestDNSRecord returns the most recently stored DNS result for a domain.
// Returns nil, nil if no record exists yet.
func (d *Database) GetLatestDNSRecord(domain string) (*DNSRecord, error) {
	var rec DNSRecord
	err := d.db.Get(&rec, `SELECT * FROM dns_records WHERE domain = ?`, domain)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
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
	eventID := fmt.Sprintf("%s-%s-%d", domain, changeType, time.Now().UnixNano())
	_, err := d.db.Exec(`
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
		WHERE subdomain LIKE ? AND status = 'open'
		ORDER BY subdomain
	`, "%"+domain)
	if err != nil && isTableNotExistsError(err) {
		return []Takeover{}, nil
	}
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
		SELECT * FROM technologies
		WHERE host LIKE ? OR host = ?
		ORDER BY host
	`, "%."+domain, domain)
	if err != nil && isTableNotExistsError(err) {
		return []Technology{}, nil
	}
	return techs, err
}

// GetDNSRecordsForDomain returns DNS records for a domain
func (d *Database) GetDNSRecordsForDomain(domain string) ([]DNSRecord, error) {
	var records []DNSRecord
	err := d.db.Select(&records, `
		SELECT * FROM dns_records
		WHERE domain LIKE ? OR domain = ?
		ORDER BY domain
	`, "%."+domain, domain)
	if err != nil && isTableNotExistsError(err) {
		return []DNSRecord{}, nil
	}
	return records, err
}

// GetPortsForDomain returns all open ports for hosts under a domain
func (d *Database) GetPortsForDomain(domain string) ([]Port, error) {
	var ports []Port
	err := d.db.Select(&ports, `
		SELECT * FROM ports
		WHERE (host LIKE ? OR host = ?) AND state = 'open'
		ORDER BY host, port
	`, "%."+domain, domain)
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
	SubdomainCount   int
	PortCount        int
	CertificateCount int
	TechnologyCount  int
	DNSRecordCount   int
	VulnCount        int
	URLCount         int
	APICount         int
	EmailCount       int
	CloudCount       int
	TakeoverCount    int
}

// UpdateDomainLastScanned updates the last_scanned timestamp for a domain
func (d *Database) UpdateDomainLastScanned(domain string) error {
	_, err := d.db.Exec(`
		UPDATE domains SET last_scanned = CURRENT_TIMESTAMP WHERE domain = ?
	`, domain)
	return err
}

// SaveTechnology upserts a technology fingerprint result for a host
func (d *Database) SaveTechnology(host string, statusCode int, title, server, techJSON, headersJSON string, contentLength int64, redirectURL string) error {
	_, err := d.db.Exec(`
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
	_, err := d.db.Exec(`
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
	_, err := d.db.Exec(`
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
	_, err := d.db.Exec(`
		INSERT INTO urls (domain, url, category, interesting, source)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			category = excluded.category,
			interesting = excluded.interesting,
			source = excluded.source
	`, domain, url, category, interesting, source)
	return err
}

// SaveAPI upserts a discovered API endpoint
func (d *Database) SaveAPI(url, apiType, title, version string, endpointsCount int, endpointsJSON string) error {
	_, err := d.db.Exec(`
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
	_, err := d.db.Exec(`
		INSERT INTO emails (domain, email, source)
		VALUES (?, ?, ?)
		ON CONFLICT(email) DO NOTHING
	`, domain, email, source)
	return err
}

// SaveCloudBucket upserts a cloud storage bucket
func (d *Database) SaveCloudBucket(provider, bucketName, url, domain, accessLevel, severity, evidence string) error {
	_, err := d.db.Exec(`
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

	// Count subdomains
	if err := d.db.Get(&stats.SubdomainCount, `
		SELECT COUNT(*) FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ? AND s.active = 1
	`, domain); err != nil {
		return nil, fmt.Errorf("failed to count subdomains: %w", err)
	}

	// Count ports
	if err := d.db.Get(&stats.PortCount, `
		SELECT COUNT(*) FROM ports
		WHERE (host LIKE ? OR host = ?) AND state = 'open'
	`, "%."+domain, domain); err != nil {
		return nil, fmt.Errorf("failed to count ports: %w", err)
	}

	// Count certificates
	if err := d.db.Get(&stats.CertificateCount, `
		SELECT COUNT(*) FROM certificates
		WHERE host LIKE ? OR host = ?
	`, "%."+domain, domain); err != nil {
		return nil, fmt.Errorf("failed to count certificates: %w", err)
	}

	// Count technologies
	if err := d.db.Get(&stats.TechnologyCount, `
		SELECT COUNT(*) FROM technologies
		WHERE host LIKE ? OR host = ?
	`, "%."+domain, domain); err != nil {
		return nil, fmt.Errorf("failed to count technologies: %w", err)
	}

	// Count DNS records
	if err := d.db.Get(&stats.DNSRecordCount, `
		SELECT COUNT(*) FROM dns_records
		WHERE domain LIKE ? OR domain = ?
	`, "%."+domain, domain); err != nil {
		return nil, fmt.Errorf("failed to count DNS records: %w", err)
	}

	// Count vulns
	if err := d.db.Get(&stats.VulnCount, `
		SELECT COUNT(*) FROM findings
		WHERE host LIKE ? AND status = 'open'
	`, "%"+domain); err != nil {
		return nil, fmt.Errorf("failed to count findings: %w", err)
	}

	// Count URLs
	if err := d.db.Get(&stats.URLCount, `
		SELECT COUNT(*) FROM urls
		WHERE domain = ? OR domain LIKE ?
	`, domain, "%."+domain); err != nil {
		return nil, fmt.Errorf("failed to count URLs: %w", err)
	}

	// Count APIs
	if err := d.db.Get(&stats.APICount, `
		SELECT COUNT(*) FROM apis
		WHERE url LIKE ?
	`, "%"+domain+"%"); err != nil {
		return nil, fmt.Errorf("failed to count APIs: %w", err)
	}

	// Count emails
	if err := d.db.Get(&stats.EmailCount, `
		SELECT COUNT(*) FROM emails
		WHERE domain = ?
	`, domain); err != nil {
		return nil, fmt.Errorf("failed to count emails: %w", err)
	}

	// Count cloud storage
	if err := d.db.Get(&stats.CloudCount, `
		SELECT COUNT(*) FROM cloud_storage
		WHERE domain = ?
	`, domain); err != nil {
		return nil, fmt.Errorf("failed to count cloud storage: %w", err)
	}

	// Count takeovers
	if err := d.db.Get(&stats.TakeoverCount, `
		SELECT COUNT(*) FROM takeovers
		WHERE subdomain LIKE ? AND status = 'open'
	`, "%"+domain); err != nil {
		return nil, fmt.Errorf("failed to count takeovers: %w", err)
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
