package commands

import (
	"database/sql"
	"fmt"

	"github.com/asm-tool/asm-go/internal/dashboard"
	"github.com/asm-tool/asm-go/internal/database"
)

const (
	domainDetailPreviewLimit = 25
	domainModalURLLimit      = 500
)

func getPageData(deps *Deps, activePage string) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: activePage,
	}

	stats, err := deps.DB.GetStats()
	if err != nil {
		data.Warning = "Failed to load dashboard statistics"
	} else {
		data.Stats = statsView(stats)
	}

	findings, err := deps.DB.GetFindingSeverityCounts()
	if err != nil {
		if data.Warning == "" {
			data.Warning = "Failed to load finding counts"
		}
	} else {
		data.Findings = findingCountsView(findings)
	}

	if domains, err := deps.DB.GetDomainsWithStats(); err == nil {
		data.Domains = domainStatsFromRows(domains)
	}

	if changes, err := deps.DB.GetChangeEvents("", 50); err == nil {
		data.ChangeEvents = mapSlice(changes, changeEventView)
	}

	return data
}

func loadGlobalList(deps *Deps, kind, title string) (*dashboard.GlobalListData, error) {
	list := &dashboard.GlobalListData{Title: title}

	switch kind {
	case "subdomains":
		rows, err := deps.DB.GetAllSubdomains()
		if err != nil {
			return nil, fmt.Errorf("failed to load subdomains: %w", err)
		}
		list.Subdomains = mapSlice(rows, subdomainView)
	case "ports":
		rows, err := deps.DB.GetAllPorts()
		if err != nil {
			return nil, fmt.Errorf("failed to load ports: %w", err)
		}
		list.Ports = mapSlice(rows, portView)
	case "certificates":
		rows, err := deps.DB.GetAllCertificates()
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates: %w", err)
		}
		list.Certificates = mapSlice(rows, certificateView)
	case "urls":
		rows, err := deps.DB.GetAllURLs()
		if err != nil {
			return nil, fmt.Errorf("failed to load URLs: %w", err)
		}
		list.URLs = mapSlice(rows, urlView)
	case "apis":
		rows, err := deps.DB.GetAllAPIs()
		if err != nil {
			return nil, fmt.Errorf("failed to load APIs: %w", err)
		}
		list.APIs = mapSlice(rows, apiView)
	case "cloud":
		rows, err := deps.DB.GetAllCloudStorage()
		if err != nil {
			return nil, fmt.Errorf("failed to load cloud storage: %w", err)
		}
		list.CloudStorage = mapSlice(rows, cloudStorageView)
	case "findings":
		rows, err := deps.DB.GetAllFindings()
		if err != nil {
			return nil, fmt.Errorf("failed to load findings: %w", err)
		}
		list.Findings = mapSlice(rows, findingView)
	case "takeovers":
		rows, err := deps.DB.GetAllTakeovers()
		if err != nil {
			return nil, fmt.Errorf("failed to load takeovers: %w", err)
		}
		list.Takeovers = mapSlice(rows, takeoverView)
	}

	return list, nil
}

func loadDomainDetailPageData(deps *Deps, domainName, only string, previewLimit, urlLimit int) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: "domains",
	}

	domain, err := deps.DB.Domains.GetByName(domainName)
	if err != nil {
		data.Error = "Domain not found"
		return data
	}

	detail := &dashboard.DomainDetailData{
		Domain:      domain.Domain,
		AddedAt:     domain.AddedAt,
		LastScanned: domain.LastScanned,
	}

	stats, err := deps.DB.GetDomainDetailStats(domainName)
	if err != nil {
		addPageWarning(&data, "Failed to load domain statistics")
	} else if stats != nil {
		detail.Stats = dashboard.DomainDetailStats{
			SubdomainCount:   stats.SubdomainCount,
			PortCount:        stats.PortCount,
			CertificateCount: stats.CertificateCount,
			TechnologyCount:  stats.TechnologyCount,
			DNSRecordCount:   stats.DNSRecordCount,
			VulnCount:        stats.VulnCount,
			URLCount:         stats.URLCount,
			APICount:         stats.APICount,
			CloudCount:       stats.CloudCount,
			TakeoverCount:    stats.TakeoverCount,
		}
	}

	if wantDomainAsset(only, "subdomains") {
		detail.Subdomains = loadDomainAssets(&data, "Failed to load subdomains", previewLimit,
			func() ([]database.Subdomain, error) { return deps.DB.GetSubdomainsForDomain(domainName) }, subdomainView)
	}
	if wantDomainAsset(only, "ports") {
		detail.Ports = loadDomainAssets(&data, "Failed to load open ports", previewLimit,
			func() ([]database.Port, error) { return deps.DB.GetPortsForDomain(domainName) }, portView)
	}
	if wantDomainAsset(only, "certificates") {
		detail.Certificates = loadDomainAssets(&data, "Failed to load certificates", previewLimit,
			func() ([]database.Certificate, error) { return deps.DB.GetCertificatesForDomain(domainName) }, certificateView)
	}
	if wantDomainAsset(only, "technologies") {
		detail.Technologies = loadDomainAssets(&data, "Failed to load technologies", previewLimit,
			func() ([]database.Technology, error) { return deps.DB.GetTechnologiesForDomain(domainName) }, technologyView)
	}
	if wantDomainAsset(only, "dns") {
		detail.DNSRecords = loadDomainAssets(&data, "Failed to load DNS records", previewLimit,
			func() ([]database.DNSRecord, error) { return deps.DB.GetDNSRecordsForDomain(domainName) }, dnsRecordView)
	}
	if wantDomainAsset(only, "vulnerabilities") {
		detail.Findings = loadDomainAssets(&data, "Failed to load vulnerabilities", previewLimit,
			func() ([]database.Finding, error) { return deps.DB.GetVulnerabilitiesForDomain(domainName) }, findingView)
	}
	if wantDomainAsset(only, "urls") {
		detail.URLs = loadDomainAssets(&data, "Failed to load URLs", previewLimit,
			func() ([]database.URL, error) { return deps.DB.GetURLsForDomainLimit(domainName, urlLimit) }, urlView)
	}
	if wantDomainAsset(only, "apis") {
		detail.APIs = loadDomainAssets(&data, "Failed to load APIs", previewLimit,
			func() ([]database.API, error) { return deps.DB.GetAPIsForDomain(domainName) }, apiView)
	}
	if wantDomainAsset(only, "cloud") {
		detail.CloudStorage = loadDomainAssets(&data, "Failed to load cloud storage", previewLimit,
			func() ([]database.CloudStorage, error) { return deps.DB.GetCloudStorageForDomain(domainName) }, cloudStorageView)
	}
	if wantDomainAsset(only, "takeovers") {
		detail.Takeovers = loadDomainAssets(&data, "Failed to load takeovers", previewLimit,
			func() ([]database.Takeover, error) { return deps.DB.GetTakeoversForDomain(domainName) }, takeoverView)
	}

	if only == "" {
		if changes, err := deps.DB.GetChangeEvents(domainName, 100); err != nil {
			addPageWarning(&data, "Failed to load change events")
		} else {
			detail.ChangeEvents = mapSlice(changes, changeEventView)
		}
	}

	data.DomainDetail = detail
	return data
}

func loadDomainAssets[T any, V any](data *dashboard.PageData, warn string, previewLimit int, load func() ([]T, error), view func(T) V) []V {
	rows, err := load()
	if err != nil {
		addPageWarning(data, warn)
		return nil
	}
	return previewList(mapSlice(rows, view), previewLimit)
}

func wantDomainAsset(only, kind string) bool {
	return only == "" || only == kind
}

func previewList[T any](items []T, n int) []T {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func addPageWarning(data *dashboard.PageData, msg string) {
	if data.Warning == "" {
		data.Warning = msg
		return
	}
	data.Warning += "; " + msg
}

func mapSlice[In any, Out any](in []In, f func(In) Out) []Out {
	out := make([]Out, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

func statsView(s *database.Stats) dashboard.Stats {
	if s == nil {
		return dashboard.Stats{}
	}
	return dashboard.Stats{
		Domains:      s.Domains,
		Subdomains:   s.Subdomains,
		Ports:        s.Ports,
		Certificates: s.Certificates,
		URLs:         s.URLs,
		APIs:         s.APIs,
		CloudBuckets: s.CloudBuckets,
		Takeovers:    s.Takeovers,
	}
}

func findingCountsView(f *database.FindingSeverityCounts) dashboard.FindingCounts {
	if f == nil {
		return dashboard.FindingCounts{}
	}
	return dashboard.FindingCounts{
		Critical: f.Critical,
		High:     f.High,
		Medium:   f.Medium,
		Low:      f.Low,
		Info:     f.Info,
		Total:    f.Critical + f.High + f.Medium + f.Low + f.Info,
	}
}

func domainStatsFromRows(rows []database.DomainWithStats) []dashboard.DomainStats {
	return mapSlice(rows, func(d database.DomainWithStats) dashboard.DomainStats {
		return dashboard.DomainStats{
			ID:             d.ID,
			Domain:         d.Domain,
			AddedAt:        d.AddedAt,
			LastScanned:    d.LastScanned,
			SubdomainCount: d.SubdomainCount,
			PortCount:      d.PortCount,
			CriticalCount:  d.CriticalCount,
			HighCount:      d.HighCount,
		}
	})
}

func subdomainView(s database.Subdomain) dashboard.SubdomainView {
	return dashboard.SubdomainView{Subdomain: s.Subdomain, DiscoveredAt: s.DiscoveredAt, LastSeen: s.LastSeen}
}

func portView(p database.Port) dashboard.PortView {
	return dashboard.PortView{
		Host: p.Host, Port: p.Port, Protocol: p.Protocol, Service: p.Service,
		Version: p.Version, Product: p.Product, State: p.State, Banner: p.Banner,
		DiscoveredAt: p.DiscoveredAt,
	}
}

func certificateView(c database.Certificate) dashboard.CertificateView {
	return dashboard.CertificateView{
		Host: c.Host, Port: c.Port, Subject: c.Subject, Issuer: c.Issuer,
		NotAfter: c.NotAfter, DaysUntilExpiry: c.DaysUntilExpiry, SAN: c.SAN,
	}
}

func technologyView(t database.Technology) dashboard.TechnologyView {
	return dashboard.TechnologyView{
		Host: t.Host, StatusCode: t.StatusCode, Title: t.Title, Server: t.Server,
		Technologies: t.Technologies, CheckedAt: t.CheckedAt,
	}
}

func dnsRecordView(d database.DNSRecord) dashboard.DNSRecordView {
	return dashboard.DNSRecordView{Domain: d.Domain, Records: d.Records, CheckedAt: d.CheckedAt}
}

func findingView(f database.Finding) dashboard.FindingView {
	return dashboard.FindingView{
		ID: f.ID, Name: f.Name, Severity: f.Severity, Description: f.Description,
		Host: f.Host, MatchedAt: f.MatchedAt, Tags: f.Tags, DiscoveredAt: f.DiscoveredAt,
	}
}

func urlView(u database.URL) dashboard.URLView {
	return dashboard.URLView{
		URL: u.URL, Domain: u.Domain, Category: nullString(u.Category),
		Interesting: u.Interesting > 0, Source: u.Source, DiscoveredAt: u.DiscoveredAt,
	}
}

func apiView(a database.API) dashboard.APIView {
	return dashboard.APIView{
		URL: a.URL, Type: nullString(a.Type), Title: nullString(a.Title),
		Version: nullString(a.Version), DiscoveredAt: a.DiscoveredAt,
	}
}

func cloudStorageView(c database.CloudStorage) dashboard.CloudStorageView {
	return dashboard.CloudStorageView{
		Provider: c.Provider, BucketName: c.BucketName, URL: c.URL,
		AccessLevel: c.AccessLevel, Severity: c.Severity, Evidence: c.Evidence, Status: c.Status,
	}
}

func takeoverView(t database.Takeover) dashboard.TakeoverView {
	return dashboard.TakeoverView{
		Subdomain: t.Subdomain, CNAME: t.CNAME, Service: t.Service,
		TakeoverType: t.TakeoverType, Confidence: t.Confidence, Evidence: t.Evidence,
		DiscoveredAt: t.DiscoveredAt,
	}
}

func changeEventView(c database.ChangeEvent) dashboard.ChangeEventView {
	return dashboard.ChangeEventView{
		Domain: c.Domain, ChangeType: c.ChangeType, Severity: c.Severity,
		Description: c.Description, OldValue: c.OldValue, NewValue: c.NewValue, Timestamp: c.Timestamp,
	}
}

func nullString(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}
