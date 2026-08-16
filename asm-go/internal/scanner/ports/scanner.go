package ports

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result represents a port scan result for a single host
type Result struct {
	Host      string
	OpenPorts []Port
	Duration  time.Duration
	Error     string
}

// Port represents an open port with service information
type Port struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Version  string
	Banner   string
}

// Scanner performs high-speed port scanning
type Scanner struct {
	Workers       int
	Timeout       time.Duration
	GrabBanner    bool
	BannerTimeout time.Duration
}

// DefaultScanner returns a scanner with sensible defaults
func DefaultScanner() *Scanner {
	return &Scanner{
		Workers:       500,             // Concurrent connections
		Timeout:       2 * time.Second, // Connection timeout
		GrabBanner:    true,
		BannerTimeout: 3 * time.Second,
	}
}

// NewScanner creates a scanner with custom settings
func NewScanner(workers int, timeout time.Duration) *Scanner {
	s := DefaultScanner()
	if workers > 0 {
		s.Workers = workers
	}
	if timeout > 0 {
		s.Timeout = timeout
	}
	return s
}

// Scan scans a single host for open ports
func (s *Scanner) Scan(ctx context.Context, host string, ports []int) *Result {
	start := time.Now()
	result := &Result{Host: host}

	if len(ports) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	// Channel for jobs and results
	jobs := make(chan int, len(ports))
	results := make(chan Port, len(ports))

	// Limit workers to port count if fewer ports
	workers := s.Workers
	if len(ports) < workers {
		workers = len(ports)
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					if p := s.scanPort(ctx, host, port); p != nil {
						select {
						case results <- *p:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- port:
			}
		}
		close(jobs)
	}()

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for port := range results {
		result.OpenPorts = append(result.OpenPorts, port)
	}

	// Sort by port number
	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Port < result.OpenPorts[j].Port
	})

	result.Duration = time.Since(start)
	return result
}

// ScanBatch scans multiple hosts in parallel
func (s *Scanner) ScanBatch(ctx context.Context, hosts []string, ports []int) []*Result {
	if len(hosts) == 0 {
		return nil
	}

	results := make([]*Result, len(hosts))
	var wg sync.WaitGroup

	// Limit concurrent hosts to avoid overwhelming the system
	sem := make(chan struct{}, 10) // Max 10 hosts at once

	for i, host := range hosts {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = s.Scan(ctx, h, ports)
		}(i, host)
	}

	wg.Wait()
	return results
}

// isTLSPort returns true for ports that speak TLS natively.
func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 465, 636, 993, 995, 5986:
		return true
	}
	return false
}

// scanPort attempts to connect to a single port
func (s *Scanner) scanPort(ctx context.Context, host string, port int) *Port {
	address := fmt.Sprintf("%s:%d", host, port)

	d := net.Dialer{Timeout: s.Timeout}
	rawConn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer rawConn.Close()

	p := &Port{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  guessService(port),
	}

	// Upgrade to TLS if needed
	var conn net.Conn = rawConn
	if isTLSPort(port) {
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // banner grab only, not validating certs
			ServerName:         host,
		})
		if err := tlsConn.SetDeadline(time.Now().Add(s.BannerTimeout)); err == nil {
			if err := tlsConn.Handshake(); err == nil {
				conn = tlsConn
			}
		}
	}

	// Attempt banner grab if enabled
	if s.GrabBanner {
		if banner := s.grabBanner(conn, host, port); banner != "" {
			p.Banner = banner
			if version := extractVersion(banner, p.Service); version != "" {
				p.Version = version
			}
		}
	}

	return p
}

// grabBanner attempts to read a service banner, sending a probe if needed.
func (s *Scanner) grabBanner(conn net.Conn, host string, port int) string {
	_ = conn.SetDeadline(time.Now().Add(s.BannerTimeout))

	probe := getProbe(host, port)
	if probe != "" {
		_, _ = conn.Write([]byte(probe))
	}

	// Read up to 4 KB in chunks to handle slow/chunked services
	lr := io.LimitReader(conn, 4096)
	raw, err := io.ReadAll(lr)
	if err != nil && len(raw) == 0 {
		return ""
	}

	banner := strings.TrimSpace(string(raw))
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	// Truncate display to 512 chars
	if len(banner) > 512 {
		banner = banner[:512]
	}

	return banner
}

// getProbe returns an optional probe for a port.
func getProbe(host string, port int) string {
	switch port {
	case 80, 8080, 8000:
		return fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	case 443, 8443:
		return fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	case 21:
		return "" // FTP sends banner immediately
	case 25, 587:
		return "EHLO asm-tool\r\n"
	case 110:
		return "" // POP3 sends banner immediately
	case 143:
		return "" // IMAP sends banner immediately
	default:
		return ""
	}
}

// extractVersion attempts to extract version information from a banner.
func extractVersion(banner, service string) string {
	lower := strings.ToLower(banner)

	switch service {
	case "ssh":
		// SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
		if idx := strings.Index(lower, "ssh-"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], " \r\n")
			if end > 0 {
				return banner[idx : idx+end]
			}
			return banner[idx:]
		}

	case "http", "http-proxy", "https", "https-alt", "http-alt":
		// Server: nginx/1.18.0 or Apache/2.4.54
		if idx := strings.Index(lower, "server: "); idx >= 0 {
			rest := banner[idx+8:]
			end := strings.IndexAny(rest, "\r\n ")
			if end > 0 {
				return strings.TrimSpace(rest[:end])
			}
			if len(rest) > 0 {
				return strings.TrimSpace(rest)
			}
		}

	case "ftp":
		// 220 vsFTPd 3.0.3
		if strings.HasPrefix(lower, "220 ") {
			line := banner[4:]
			if end := strings.IndexAny(line, "\r\n"); end > 0 {
				return strings.TrimSpace(line[:end])
			}
			return strings.TrimSpace(line)
		}

	case "smtp", "submission":
		// 220 mail.example.com ESMTP Postfix (Ubuntu)
		if strings.HasPrefix(lower, "220 ") {
			line := banner[4:]
			if end := strings.IndexAny(line, "\r\n"); end > 0 {
				return strings.TrimSpace(line[:end])
			}
			return strings.TrimSpace(line)
		}

	case "pop3", "pop3s":
		// +OK Dovecot ready.
		if strings.HasPrefix(lower, "+ok ") {
			return strings.TrimSpace(banner[4:])
		}

	case "imap", "imaps":
		// * OK [CAPABILITY ...] Dovecot ready.
		if strings.HasPrefix(lower, "* ok ") {
			return strings.TrimSpace(banner[5:])
		}

	case "redis":
		// -ERR ... or +PONG
		return strings.TrimSpace(banner)

	case "mongodb":
		// Raw binary but may contain version string
		if idx := strings.Index(banner, "version"); idx >= 0 {
			return banner[idx : min(idx+30, len(banner))]
		}
	}

	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// guessService returns the common service name for a port
func guessService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		161:   "snmp",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		587:   "submission",
		636:   "ldaps",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		1723:  "pptp",
		2049:  "nfs",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		5900:  "vnc",
		5985:  "wsman",
		6379:  "redis",
		8000:  "http-alt",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		11211: "memcached",
		27017: "mongodb",
		27018: "mongodb",
	}

	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

// CommonPorts returns the most commonly open ports
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
		465, 587, 636, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432,
		5900, 5985, 6379, 8000, 8080, 8443, 9200, 11211, 27017,
	}
}

// Top100Ports returns the top 100 most commonly open ports
func Top100Ports() []int {
	return []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
		113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
		513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
		1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
		2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
		5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
		6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
		32768, 49152, 49153, 49154, 49155, 49156, 49157,
	}
}

// PortRange generates a slice of ports from start to end (inclusive)
func PortRange(start, end int) []int {
	if start > end || start < 1 || end > 65535 {
		return nil
	}
	ports := make([]int, end-start+1)
	for i := range ports {
		ports[i] = start + i
	}
	return ports
}

// Config holds configuration for a port scan.
type Config struct {
	Workers       int
	Timeout       time.Duration
	GrabBanner    bool
	BannerTimeout time.Duration
	Ports         []int // nil = use CommonPorts
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Workers:       500,
		Timeout:       2 * time.Second,
		GrabBanner:    true,
		BannerTimeout: 3 * time.Second,
	}
}

// ScanResult holds the result of a batch port scan.
type ScanResult struct {
	Results  []*Result
	Duration time.Duration
	Err      error
}

// Scan performs a batch port scan over hosts and returns results per host.
// It is the deep entry point — all configuration and batching happens inside.
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
	portsToScan := cfg.Ports
	if len(portsToScan) == 0 {
		portsToScan = CommonPorts()
	}

	scanner := Scanner{
		Workers:       cfg.Workers,
		Timeout:       cfg.Timeout,
		GrabBanner:    cfg.GrabBanner,
		BannerTimeout: cfg.BannerTimeout,
	}

	start := time.Now()
	raw := scanner.ScanBatch(ctx, hosts, portsToScan)

	var errs []string
	for _, r := range raw {
		if r == nil {
			continue
		}
		if r.Error != "" {
			errs = append(errs, r.Error)
		}
	}

	return &ScanResult{
		Results:  raw,
		Duration: time.Since(start),
		Err:      joinErrors(errs),
	}
}

// joinErrors returns nil for empty, otherwise an errors.Join.
func joinErrors(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	errs2 := make([]error, len(errs))
	for i, e := range errs {
		errs2[i] = fmt.Errorf("%s", e)
	}
	return fmt.Errorf("%w", errors.Join(errs2...))
}
