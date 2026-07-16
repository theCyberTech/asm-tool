package dns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Record represents a DNS record
type Record struct {
	Type     string
	Value    string
	TTL      uint32
	Priority uint16 // For MX records
}

// SOARecord holds SOA record fields
type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinTTL     uint32
}

// CAARecord represents a Certification Authority Authorization record
type CAARecord struct {
	Flags uint8
	Tag   string // "issue", "issuewild", "iodef"
	Value string
}

// DNSSECResult holds DNSSEC status for a domain
type DNSSECResult struct {
	Signed    bool // AD flag set by validating resolver — chain of trust intact
	HasDNSKEY bool // DNSKEY records present at the domain
	HasDS     bool // DS record present at parent zone
	HasRRSIG  bool // RRSIG records present in responses
}

// ChangeEvent describes a detected DNS change vs. a previous scan
type ChangeEvent struct {
	Type        string // record_added, record_removed, record_changed, soa_serial_changed
	RecordType  string
	OldValue    string
	NewValue    string
	Description string
}

// Result represents DNS lookup results for a domain
type Result struct {
	Domain    string
	Records   map[string][]Record // Type -> Records
	SOA       *SOARecord
	CAA       []CAARecord
	DNSSEC    *DNSSECResult
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
	Record   string
	Policy   string // none, quarantine, reject
	Valid    bool
	Warnings []string
}

// Monitor performs DNS lookups and monitoring
type Monitor struct {
	DNSServer string // e.g. "8.8.8.8:53"
	Timeout   time.Duration
	Workers   int
}

// DefaultMonitor returns a monitor with sensible defaults
func DefaultMonitor() *Monitor {
	return &Monitor{
		DNSServer: "8.8.8.8:53",
		Timeout:   5 * time.Second,
		Workers:   20,
	}
}

// NewMonitor creates a monitor with custom DNS servers
func NewMonitor(servers []string, timeout time.Duration) *Monitor {
	m := DefaultMonitor()
	if timeout > 0 {
		m.Timeout = timeout
	}

	if len(servers) > 0 {
		addr := servers[0]
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		m.DNSServer = addr
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

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Standard record types via net.Resolver
	stdTypes := []struct {
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

	for _, rt := range stdTypes {
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

	// SOA, CAA, DNSSEC via miekg/dns (parallel with standard lookups)
	wg.Add(1)
	go func() {
		defer wg.Done()
		soa := m.lookupSOA(ctx, domain)
		mu.Lock()
		result.SOA = soa
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		caa := m.lookupCAA(ctx, domain)
		mu.Lock()
		result.CAA = caa
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		dnssec := m.checkDNSSEC(ctx, domain)
		mu.Lock()
		result.DNSSEC = dnssec
		mu.Unlock()
	}()

	wg.Wait()

	// Analyze SPF and DMARC from TXT records
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

// DetectChanges compares the current result against a previous one and returns
// a list of changes. previous may be nil (first scan).
func DetectChanges(current, previous *Result) []ChangeEvent {
	if previous == nil {
		return nil
	}

	var changes []ChangeEvent

	// Compare each standard record type
	for _, rtype := range []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"} {
		curr := recordValues(current.Records[rtype])
		prev := recordValues(previous.Records[rtype])

		// In curr but not in prev → newly added
		for _, v := range setDiff(curr, prev) {
			changes = append(changes, ChangeEvent{
				Type:        "record_added",
				RecordType:  rtype,
				NewValue:    v,
				Description: fmt.Sprintf("%s record added: %s", rtype, v),
			})
		}
		// In prev but not in curr → removed since last scan
		for _, v := range setDiff(prev, curr) {
			changes = append(changes, ChangeEvent{
				Type:        "record_removed",
				RecordType:  rtype,
				OldValue:    v,
				Description: fmt.Sprintf("%s record removed: %s", rtype, v),
			})
		}
	}

	// SOA serial change
	if current.SOA != nil && previous.SOA != nil {
		if current.SOA.Serial != previous.SOA.Serial {
			changes = append(changes, ChangeEvent{
				Type:        "soa_serial_changed",
				RecordType:  "SOA",
				OldValue:    fmt.Sprintf("%d", previous.SOA.Serial),
				NewValue:    fmt.Sprintf("%d", current.SOA.Serial),
				Description: fmt.Sprintf("SOA serial changed: %d → %d", previous.SOA.Serial, current.SOA.Serial),
			})
		}
	}

	// CAA changes
	currCAA := caaValues(current.CAA)
	prevCAA := caaValues(previous.CAA)
	// In curr but not in prev → added
	for _, v := range setDiff(currCAA, prevCAA) {
		changes = append(changes, ChangeEvent{
			Type:        "record_added",
			RecordType:  "CAA",
			NewValue:    v,
			Description: fmt.Sprintf("CAA record added: %s", v),
		})
	}
	// In prev but not in curr → removed
	for _, v := range setDiff(prevCAA, currCAA) {
		changes = append(changes, ChangeEvent{
			Type:        "record_removed",
			RecordType:  "CAA",
			OldValue:    v,
			Description: fmt.Sprintf("CAA record removed: %s", v),
		})
	}

	// DNSSEC status change
	if current.DNSSEC != nil && previous.DNSSEC != nil {
		if current.DNSSEC.Signed != previous.DNSSEC.Signed {
			status := "enabled"
			if !current.DNSSEC.Signed {
				status = "disabled"
			}
			changes = append(changes, ChangeEvent{
				Type:        "record_changed",
				RecordType:  "DNSSEC",
				OldValue:    fmt.Sprintf("signed=%v", previous.DNSSEC.Signed),
				NewValue:    fmt.Sprintf("signed=%v", current.DNSSEC.Signed),
				Description: fmt.Sprintf("DNSSEC %s", status),
			})
		}
	}

	return changes
}

// ── miekg/dns helpers ───────────────────────────────────────────────────────

func (m *Monitor) dnsQuery(ctx context.Context, domain, qtype string, setBits func(*dns.Msg)) (*dns.Msg, error) {
	c := &dns.Client{Timeout: m.Timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.StringToType[qtype])
	msg.RecursionDesired = true
	if setBits != nil {
		setBits(msg)
	}
	resp, _, err := c.ExchangeContext(ctx, msg, m.DNSServer)
	return resp, err
}

func (m *Monitor) lookupSOA(ctx context.Context, domain string) *SOARecord {
	resp, err := m.dnsQuery(ctx, domain, "SOA", nil)
	if err != nil || resp == nil {
		return nil
	}

	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return &SOARecord{
				PrimaryNS:  strings.TrimSuffix(soa.Ns, "."),
				AdminEmail: strings.TrimSuffix(soa.Mbox, "."),
				Serial:     soa.Serial,
				Refresh:    soa.Refresh,
				Retry:      soa.Retry,
				Expire:     soa.Expire,
				MinTTL:     soa.Minttl,
			}
		}
	}

	// SOA may be in the Authority section when querying apex
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return &SOARecord{
				PrimaryNS:  strings.TrimSuffix(soa.Ns, "."),
				AdminEmail: strings.TrimSuffix(soa.Mbox, "."),
				Serial:     soa.Serial,
				Refresh:    soa.Refresh,
				Retry:      soa.Retry,
				Expire:     soa.Expire,
				MinTTL:     soa.Minttl,
			}
		}
	}

	return nil
}

func (m *Monitor) lookupCAA(ctx context.Context, domain string) []CAARecord {
	resp, err := m.dnsQuery(ctx, domain, "CAA", nil)
	if err != nil || resp == nil {
		return nil
	}

	var records []CAARecord
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			records = append(records, CAARecord{
				Flags: caa.Flag,
				Tag:   caa.Tag,
				Value: caa.Value,
			})
		}
	}
	return records
}

func (m *Monitor) checkDNSSEC(ctx context.Context, domain string) *DNSSECResult {
	result := &DNSSECResult{}

	// Query DNSKEY with DO bit — a validating resolver sets AD if the chain is valid
	resp, err := m.dnsQuery(ctx, domain, "DNSKEY", func(msg *dns.Msg) {
		msg.SetEdns0(4096, true) // DO bit
	})
	if err == nil && resp != nil {
		result.Signed = resp.AuthenticatedData // AD flag from validating resolver
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.DNSKEY:
				result.HasDNSKEY = true
			case *dns.RRSIG:
				result.HasRRSIG = true
			}
		}
	}

	// Query DS record (at parent zone) to confirm delegation is signed
	resp, err = m.dnsQuery(ctx, domain, "DS", func(msg *dns.Msg) {
		msg.SetEdns0(4096, true)
	})
	if err == nil && resp != nil {
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.DS); ok {
				result.HasDS = true
				break
			}
		}
	}

	return result
}

// ── miekg/dns standard record lookups (with TTL) ────────────────────────────

func (m *Monitor) lookupA(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "A", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			records = append(records, Record{Type: "A", Value: a.A.String(), TTL: rr.Header().Ttl})
		}
	}
	return records, nil
}

func (m *Monitor) lookupAAAA(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "AAAA", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			records = append(records, Record{Type: "AAAA", Value: aaaa.AAAA.String(), TTL: rr.Header().Ttl})
		}
	}
	return records, nil
}

func (m *Monitor) lookupCNAME(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "CNAME", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			val := strings.TrimSuffix(cname.Target, ".")
			if val != "" && val != domain {
				records = append(records, Record{Type: "CNAME", Value: val, TTL: rr.Header().Ttl})
			}
		}
	}
	return records, nil
}

func (m *Monitor) lookupMX(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "MX", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			records = append(records, Record{
				Type:     "MX",
				Value:    strings.TrimSuffix(mx.Mx, "."),
				TTL:      rr.Header().Ttl,
				Priority: mx.Preference,
			})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})
	return records, nil
}

func (m *Monitor) lookupNS(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "NS", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			records = append(records, Record{
				Type:  "NS",
				Value: strings.TrimSuffix(ns.Ns, "."),
				TTL:   rr.Header().Ttl,
			})
		}
	}
	return records, nil
}

func (m *Monitor) lookupTXT(ctx context.Context, domain string) ([]Record, error) {
	resp, err := m.dnsQuery(ctx, domain, "TXT", nil)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, Record{
				Type:  "TXT",
				Value: strings.Join(txt.Txt, ""),
				TTL:   rr.Header().Ttl,
			})
		}
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
	resp, err := m.dnsQuery(ctx, "_dmarc."+domain, "TXT", nil)
	if err != nil || resp == nil {
		return nil
	}

	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		val := strings.Join(txt.Txt, "")
		if strings.HasPrefix(strings.ToLower(val), "v=dmarc1") {
			result := &DMARCResult{
				Record: val,
				Valid:  true,
			}
			for _, part := range strings.Split(val, ";") {
				lower := strings.ToLower(strings.TrimSpace(part))
				if strings.HasPrefix(lower, "p=") {
					result.Policy = strings.TrimPrefix(lower, "p=")
				}
			}
			if result.Policy == "none" {
				result.Warnings = append(result.Warnings, "DMARC policy is 'none' - no enforcement")
			}
			return result
		}
	}
	return nil
}

// ── Change detection helpers ─────────────────────────────────────────────────

func recordValues(records []Record) []string {
	vals := make([]string, 0, len(records))
	for _, r := range records {
		vals = append(vals, r.Value)
	}
	return vals
}

func caaValues(records []CAARecord) []string {
	vals := make([]string, 0, len(records))
	for _, r := range records {
		vals = append(vals, fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value))
	}
	return vals
}

// setDiff returns elements in a that are not in b.
func setDiff(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, v := range b {
		bSet[v] = true
	}
	var diff []string
	for _, v := range a {
		if !bSet[v] {
			diff = append(diff, v)
		}
	}
	return diff
}

// ── Result helpers ───────────────────────────────────────────────────────────

// RecordCount returns total number of standard records
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

// GetCNAME returns the CNAME record if it exists
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
	if r.SOA != nil {
		parts = append(parts, fmt.Sprintf("SOA(serial=%d)", r.SOA.Serial))
	}
	if len(r.CAA) > 0 {
		parts = append(parts, fmt.Sprintf("CAA:%d", len(r.CAA)))
	}
	if r.DNSSEC != nil && r.DNSSEC.Signed {
		parts = append(parts, "DNSSEC:signed")
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// Config holds configuration for DNS lookups.
type Config struct {
	DNSServer string
	Timeout   time.Duration
	Workers   int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		DNSServer: "8.8.8.8:53",
		Timeout:   5 * time.Second,
		Workers:   20,
	}
}

// Scan performs DNS lookups for all hosts and returns the results.
func Scan(ctx context.Context, cfg Config, hosts []string) ([]Result, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	monitor := Monitor{
		DNSServer: cfg.DNSServer,
		Timeout:   cfg.Timeout,
		Workers:   cfg.Workers,
	}

	results := monitor.LookupBatch(ctx, hosts)
	out := make([]Result, 0, len(results))
	for _, r := range results {
		out = append(out, *r)
	}
	return out, nil
}
