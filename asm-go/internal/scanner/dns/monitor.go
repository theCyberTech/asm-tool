package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record represents a DNS record
type Record struct {
	Type   string
	Value  string
	TTL    uint32
	Priority uint16 // For MX records
}

// Result represents DNS lookup results for a domain
type Result struct {
	Domain    string
	Records   map[string][]Record // Type -> Records
	SPF       *SPFResult
	DMARC     *DMARCResult
	CheckedAt time.Time
	Duration  time.Duration
	Error     string
}

// SPFResult represents SPF record analysis
type SPFResult struct {
	Record   string
	Valid    bool
	Warnings []string
}

// DMARCResult represents DMARC record analysis
type DMARCResult struct {
	Record  string
	Policy  string // none, quarantine, reject
	Valid   bool
	Warnings []string
}

// Monitor performs DNS lookups and monitoring
type Monitor struct {
	Resolver  *net.Resolver
	Timeout   time.Duration
	Workers   int
}

// DefaultMonitor returns a monitor with sensible defaults
func DefaultMonitor() *Monitor {
	return &Monitor{
		Resolver: net.DefaultResolver,
		Timeout:  5 * time.Second,
		Workers:  20,
	}
}

// NewMonitor creates a monitor with custom DNS servers
func NewMonitor(servers []string, timeout time.Duration) *Monitor {
	m := DefaultMonitor()
	if timeout > 0 {
		m.Timeout = timeout
	}

	if len(servers) > 0 {
		m.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", servers[0]+":53")
			},
		}
	}

	return m
}

// Lookup performs a comprehensive DNS lookup for a domain
func (m *Monitor) Lookup(ctx context.Context, domain string) *Result {
	start := time.Now()
	result := &Result{
		Domain:    domain,
		Records:   make(map[string][]Record),
		CheckedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()

	// Lookup all record types concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	recordTypes := []struct {
		name   string
		lookup func() ([]Record, error)
	}{
		{"A", func() ([]Record, error) { return m.lookupA(ctx, domain) }},
		{"AAAA", func() ([]Record, error) { return m.lookupAAAA(ctx, domain) }},
		{"CNAME", func() ([]Record, error) { return m.lookupCNAME(ctx, domain) }},
		{"MX", func() ([]Record, error) { return m.lookupMX(ctx, domain) }},
		{"NS", func() ([]Record, error) { return m.lookupNS(ctx, domain) }},
		{"TXT", func() ([]Record, error) { return m.lookupTXT(ctx, domain) }},
	}

	for _, rt := range recordTypes {
		wg.Add(1)
		go func(name string, lookup func() ([]Record, error)) {
			defer wg.Done()
			records, err := lookup()
			if err == nil && len(records) > 0 {
				mu.Lock()
				result.Records[name] = records
				mu.Unlock()
			}
		}(rt.name, rt.lookup)
	}

	wg.Wait()

	// Analyze SPF and DMARC
	result.SPF = m.analyzeSPF(result.Records["TXT"])
	result.DMARC = m.analyzeDMARC(ctx, domain)

	result.Duration = time.Since(start)
	return result
}

// LookupBatch performs DNS lookups for multiple domains
func (m *Monitor) LookupBatch(ctx context.Context, domains []string) []*Result {
	results := make([]*Result, len(domains))

	sem := make(chan struct{}, m.Workers)
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = m.Lookup(ctx, d)
		}(i, domain)
	}

	wg.Wait()
	return results
}

func (m *Monitor) lookupA(ctx context.Context, domain string) ([]Record, error) {
	ips, err := m.Resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, ip := range ips {
		records = append(records, Record{Type: "A", Value: ip.String()})
	}
	return records, nil
}

func (m *Monitor) lookupAAAA(ctx context.Context, domain string) ([]Record, error) {
	ips, err := m.Resolver.LookupIP(ctx, "ip6", domain)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, ip := range ips {
		records = append(records, Record{Type: "AAAA", Value: ip.String()})
	}
	return records, nil
}

func (m *Monitor) lookupCNAME(ctx context.Context, domain string) ([]Record, error) {
	cname, err := m.Resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return nil, err
	}

	cname = strings.TrimSuffix(cname, ".")
	if cname != "" && cname != domain {
		return []Record{{Type: "CNAME", Value: cname}}, nil
	}
	return nil, nil
}

func (m *Monitor) lookupMX(ctx context.Context, domain string) ([]Record, error) {
	mxs, err := m.Resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, mx := range mxs {
		records = append(records, Record{
			Type:     "MX",
			Value:    strings.TrimSuffix(mx.Host, "."),
			Priority: mx.Pref,
		})
	}

	// Sort by priority
	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

func (m *Monitor) lookupNS(ctx context.Context, domain string) ([]Record, error) {
	nss, err := m.Resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, ns := range nss {
		records = append(records, Record{
			Type:  "NS",
			Value: strings.TrimSuffix(ns.Host, "."),
		})
	}
	return records, nil
}

func (m *Monitor) lookupTXT(ctx context.Context, domain string) ([]Record, error) {
	txts, err := m.Resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, txt := range txts {
		records = append(records, Record{Type: "TXT", Value: txt})
	}
	return records, nil
}

func (m *Monitor) analyzeSPF(txtRecords []Record) *SPFResult {
	for _, r := range txtRecords {
		if strings.HasPrefix(strings.ToLower(r.Value), "v=spf1") {
			result := &SPFResult{
				Record: r.Value,
				Valid:  true,
			}

			// Basic SPF analysis
			lower := strings.ToLower(r.Value)
			if strings.Contains(lower, "+all") {
				result.Warnings = append(result.Warnings, "SPF allows all senders (+all)")
				result.Valid = false
			}
			if strings.Contains(lower, "?all") {
				result.Warnings = append(result.Warnings, "SPF is neutral (?all), should use -all or ~all")
			}
			if !strings.Contains(lower, "all") {
				result.Warnings = append(result.Warnings, "SPF missing 'all' mechanism")
			}

			return result
		}
	}
	return nil
}

func (m *Monitor) analyzeDMARC(ctx context.Context, domain string) *DMARCResult {
	dmarcDomain := "_dmarc." + domain
	txts, err := m.Resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return nil
	}

	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			result := &DMARCResult{
				Record: txt,
				Valid:  true,
			}

			// Extract policy
			parts := strings.Split(txt, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(strings.ToLower(part), "p=") {
					result.Policy = strings.ToLower(strings.TrimPrefix(part, "p="))
					result.Policy = strings.TrimPrefix(result.Policy, "P=")
				}
			}

			// Warnings
			if result.Policy == "none" {
				result.Warnings = append(result.Warnings, "DMARC policy is 'none' - no enforcement")
			}

			return result
		}
	}
	return nil
}

// RecordCount returns total number of records
func (r *Result) RecordCount() int {
	count := 0
	for _, records := range r.Records {
		count += len(records)
	}
	return count
}

// HasRecord checks if a specific record type exists
func (r *Result) HasRecord(recordType string) bool {
	records, ok := r.Records[recordType]
	return ok && len(records) > 0
}

// GetCNAME returns the CNAME record if exists
func (r *Result) GetCNAME() string {
	if records, ok := r.Records["CNAME"]; ok && len(records) > 0 {
		return records[0].Value
	}
	return ""
}

// Summary returns a summary string of records
func (r *Result) Summary() string {
	var parts []string
	for recordType, records := range r.Records {
		if len(records) > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", recordType, len(records)))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
