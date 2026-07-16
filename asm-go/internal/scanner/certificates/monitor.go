package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Certificate represents a TLS certificate with relevant information
type Certificate struct {
	Host               string
	Port               int
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DaysUntilExpiry    int
	Fingerprint        string
	SAN                []string
	SignatureAlgorithm string
	IsExpired          bool
	IsExpiringSoon     bool // Within 30 days
	Error              string
}

// Result represents the result of checking multiple hosts
type Result struct {
	Certificates []*Certificate
	Duration     time.Duration
	Errors       []string
}

// Monitor checks TLS certificates
type Monitor struct {
	Workers          int
	Timeout          time.Duration
	ExpiryWarnDays   int
	InsecureSkipVerify bool
}

// DefaultMonitor returns a monitor with sensible defaults
func DefaultMonitor() *Monitor {
	return &Monitor{
		Workers:        50,
		Timeout:        10 * time.Second,
		ExpiryWarnDays: 30,
	}
}

// NewMonitor creates a monitor with custom settings
func NewMonitor(workers int, timeout time.Duration) *Monitor {
	m := DefaultMonitor()
	if workers > 0 {
		m.Workers = workers
	}
	if timeout > 0 {
		m.Timeout = timeout
	}
	return m
}

// Check retrieves certificate information for a single host
func (m *Monitor) Check(ctx context.Context, host string, port int) *Certificate {
	if port == 0 {
		port = 443
	}

	cert := &Certificate{
		Host: host,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: m.InsecureSkipVerify,
		ServerName:         host,
	}

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: m.Timeout,
	}

	// Connect with context
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		cert.Error = err.Error()
		return cert
	}
	defer conn.Close()

	// Get peer certificates
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		cert.Error = "no certificates returned"
		return cert
	}

	// Extract information from the first (leaf) certificate
	x509Cert := state.PeerCertificates[0]

	cert.Subject = x509Cert.Subject.CommonName
	if cert.Subject == "" && len(x509Cert.Subject.Organization) > 0 {
		cert.Subject = x509Cert.Subject.Organization[0]
	}

	cert.Issuer = x509Cert.Issuer.CommonName
	if cert.Issuer == "" && len(x509Cert.Issuer.Organization) > 0 {
		cert.Issuer = x509Cert.Issuer.Organization[0]
	}

	cert.SerialNumber = x509Cert.SerialNumber.String()
	cert.NotBefore = x509Cert.NotBefore
	cert.NotAfter = x509Cert.NotAfter
	cert.SignatureAlgorithm = x509Cert.SignatureAlgorithm.String()

	// Calculate days until expiry
	now := time.Now()
	cert.DaysUntilExpiry = int(x509Cert.NotAfter.Sub(now).Hours() / 24)
	cert.IsExpired = now.After(x509Cert.NotAfter)
	cert.IsExpiringSoon = cert.DaysUntilExpiry <= m.ExpiryWarnDays && !cert.IsExpired

	// Generate fingerprint (SHA-256)
	fingerprint := sha256.Sum256(x509Cert.Raw)
	cert.Fingerprint = hex.EncodeToString(fingerprint[:])

	// Extract SANs (Subject Alternative Names)
	cert.SAN = extractSANs(x509Cert)

	return cert
}

// CheckBatch checks certificates for multiple hosts concurrently
func (m *Monitor) CheckBatch(ctx context.Context, hosts []string, port int) *Result {
	start := time.Now()
	result := &Result{}

	if len(hosts) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	if port == 0 {
		port = 443
	}

	// Channel for results
	results := make(chan *Certificate, len(hosts))

	// Semaphore for limiting concurrency
	sem := make(chan struct{}, m.Workers)

	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			cert := m.Check(ctx, h, port)
			results <- cert
		}(host)
	}

	// Close results when done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for cert := range results {
		if cert.Error != "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", cert.Host, cert.Error))
		}
		result.Certificates = append(result.Certificates, cert)
	}

	// Sort by expiry date (soonest first)
	sort.Slice(result.Certificates, func(i, j int) bool {
		// Put errors at the end
		if result.Certificates[i].Error != "" && result.Certificates[j].Error == "" {
			return false
		}
		if result.Certificates[i].Error == "" && result.Certificates[j].Error != "" {
			return true
		}
		return result.Certificates[i].NotAfter.Before(result.Certificates[j].NotAfter)
	})

	result.Duration = time.Since(start)
	return result
}

// GetExpiring returns certificates expiring within the specified days
func (r *Result) GetExpiring(days int) []*Certificate {
	var expiring []*Certificate
	for _, cert := range r.Certificates {
		if cert.Error == "" && cert.DaysUntilExpiry <= days && !cert.IsExpired {
			expiring = append(expiring, cert)
		}
	}
	return expiring
}

// GetExpired returns already expired certificates
func (r *Result) GetExpired() []*Certificate {
	var expired []*Certificate
	for _, cert := range r.Certificates {
		if cert.Error == "" && cert.IsExpired {
			expired = append(expired, cert)
		}
	}
	return expired
}

// extractSANs extracts Subject Alternative Names from a certificate
func extractSANs(cert *x509.Certificate) []string {
	var sans []string

	// DNS names
	sans = append(sans, cert.DNSNames...)

	// IP addresses
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Email addresses
	sans = append(sans, cert.EmailAddresses...)

	// URIs
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

// FormatExpiry returns a human-readable expiry status
func (c *Certificate) FormatExpiry() string {
	if c.IsExpired {
		return fmt.Sprintf("EXPIRED %d days ago", -c.DaysUntilExpiry)
	}
	if c.DaysUntilExpiry == 0 {
		return "EXPIRES TODAY"
	}
	if c.DaysUntilExpiry == 1 {
		return "EXPIRES TOMORROW"
	}
	if c.DaysUntilExpiry <= 7 {
		return fmt.Sprintf("EXPIRES in %d days", c.DaysUntilExpiry)
	}
	if c.DaysUntilExpiry <= 30 {
		return fmt.Sprintf("Expires in %d days", c.DaysUntilExpiry)
	}
	return fmt.Sprintf("Valid for %d days", c.DaysUntilExpiry)
}

// SANString returns SANs as a comma-separated string
func (c *Certificate) SANString() string {
	if len(c.SAN) == 0 {
		return ""
	}
	return strings.Join(c.SAN, ", ")
}

// Config holds configuration for certificate checking.
type Config struct {
	Workers          int
	Timeout          time.Duration
	ExpiryWarnDays   int
	InsecureSkipVerify bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Workers:          50,
		Timeout:          10 * time.Second,
		ExpiryWarnDays:   30,
	}
}

// ScanResult holds the result of a batch certificate scan.
type ScanResult struct {
	Certificates []*Certificate
	Duration     time.Duration
	Err          error
}

// Scan performs a batch certificate check over hosts and returns the
// aggregated result. It is the deep entry point.
func Scan(ctx context.Context, cfg Config, hosts []string) *ScanResult {
	if len(hosts) == 0 {
		return &ScanResult{}
	}

	// Apply defaults for zero-value fields.
	if cfg.Workers == 0 {
		cfg.Workers = DefaultConfig().Workers
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}

	monitor := Monitor{
		Workers:          cfg.Workers,
		Timeout:          cfg.Timeout,
		ExpiryWarnDays:   cfg.ExpiryWarnDays,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	result := monitor.CheckBatch(ctx, hosts, 443)
	return &ScanResult{
		Certificates: result.Certificates,
		Duration:     result.Duration,
		Err:          nil, // CheckBatch doesn't return errors, they're in individual certs
	}
}

// Summary represents aggregated certificate statistics
type Summary struct {
	Total      int
	Valid      int
	Expired    int
	Expiring7  int // Expiring within 7 days
	Expiring30 int // Expiring within 30 days
	Errors     int
}

// GetSummary returns aggregated statistics for a result set
func (r *Result) GetSummary() *Summary {
	s := &Summary{
		Total: len(r.Certificates),
	}

	for _, cert := range r.Certificates {
		if cert.Error != "" {
			s.Errors++
			continue
		}

		if cert.IsExpired {
			s.Expired++
		} else {
			s.Valid++
			if cert.DaysUntilExpiry <= 7 {
				s.Expiring7++
			} else if cert.DaysUntilExpiry <= 30 {
				s.Expiring30++
			}
		}
	}

	return s
}
