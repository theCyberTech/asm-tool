package ports

import (
	"context"
	"fmt"
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
						results <- *p
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

// scanPort attempts to connect to a single port
func (s *Scanner) scanPort(ctx context.Context, host string, port int) *Port {
	address := fmt.Sprintf("%s:%d", host, port)

	// Create dialer with context
	d := net.Dialer{Timeout: s.Timeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()

	p := &Port{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  guessService(port),
	}

	// Attempt banner grab if enabled
	if s.GrabBanner {
		if banner := s.grabBanner(conn, port); banner != "" {
			p.Banner = banner
			// Try to extract version from banner
			if version := extractVersion(banner, p.Service); version != "" {
				p.Version = version
			}
		}
	}

	return p
}

// grabBanner attempts to read a service banner
func (s *Scanner) grabBanner(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(s.BannerTimeout))

	// Some services need a probe first
	probe := getProbe(port)
	if probe != "" {
		conn.Write([]byte(probe))
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Clean up banner
	banner := string(buf[:n])
	banner = strings.TrimSpace(banner)
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	// Truncate if too long
	if len(banner) > 256 {
		banner = banner[:256]
	}

	return banner
}

// getProbe returns an optional probe string for a port
func getProbe(port int) string {
	switch port {
	case 80, 8080, 8000, 8443:
		return "HEAD / HTTP/1.0\r\n\r\n"
	case 443:
		return "" // TLS needs special handling
	default:
		return ""
	}
}

// extractVersion attempts to extract version information from a banner
func extractVersion(banner, service string) string {
	banner = strings.ToLower(banner)

	switch service {
	case "ssh":
		// SSH-2.0-OpenSSH_8.9p1
		if idx := strings.Index(banner, "ssh-"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], " \r\n")
			if end > 0 {
				return banner[idx : idx+end]
			}
			return banner[idx:]
		}
	case "http", "http-proxy":
		// Server: nginx/1.18.0
		if idx := strings.Index(banner, "server:"); idx >= 0 {
			line := banner[idx+7:]
			end := strings.IndexAny(line, "\r\n")
			if end > 0 {
				return strings.TrimSpace(line[:end])
			}
		}
	case "ftp":
		// 220 vsFTPd 3.0.3
		if strings.HasPrefix(banner, "220") {
			return strings.TrimPrefix(banner, "220 ")
		}
	case "smtp":
		// 220 mail.example.com ESMTP Postfix
		if strings.HasPrefix(banner, "220") {
			return strings.TrimPrefix(banner, "220 ")
		}
	}

	return ""
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
