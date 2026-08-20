package commands

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asm-tool/asm-go/internal/dashboard"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/target"
)

var globalAssetTitles = map[string]string{
	"subdomains":      "Subdomains",
	"ports":           "Open Ports",
	"certificates":    "Certificates",
	"urls":            "URLs",
	"apis":            "API Endpoints",
	"emails":          "Email Addresses",
	"cloud":           "Cloud Storage",
	"findings":        "Findings",
	"takeovers":       "Takeovers",
	"technologies":    "Technologies",
	"dns":             "DNS Records",
	"vulnerabilities": "Findings",
}

var globalListKinds = map[string]string{
	"subdomains":   "Subdomains",
	"ports":        "Open Ports",
	"certificates": "Certificates",
	"urls":         "URLs",
	"apis":         "API Endpoints",
	"emails":       "Email Addresses",
	"cloud":        "Cloud Storage",
	"findings":     "Findings",
	"takeovers":    "Takeovers",
}

func makeOverviewHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, dashboard.OverviewJSON(getPageData(deps, "dashboard")))
	}
}

func makeDomainsJSONHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/domains" {
			http.NotFound(w, r)
			return
		}

		rows, err := deps.DB.GetDomainsWithStats()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "failed to load domains",
			})
			return
		}

		filtered, err := filterDomainStats(domainStatsFromRows(rows), r.URL.Query())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"domains": dashboard.DomainsJSON(filtered),
			"count":   len(filtered),
		})
	}
}

func makeDomainAPIHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		route, ok := parseDomainAPIPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}

		decoded, err := url.PathUnescape(route.domain)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		normalized, err := target.NormalizeTarget(decoded)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if route.kind == "" {
			data := loadDomainDetailPageData(deps, normalized, "", domainDetailPreviewLimit, domainDetailPreviewLimit)
			payload := dashboard.DomainDetailJSON(data)
			if payload.Status != "ok" {
				writeJSON(w, http.StatusNotFound, payload)
				return
			}
			writeJSON(w, http.StatusOK, payload)
			return
		}

		only := route.kind
		if only == "findings" {
			only = "vulnerabilities"
		}
		urlLimit := 0
		if only == "urls" {
			urlLimit = domainModalURLLimit
		}
		data := loadDomainDetailPageData(deps, normalized, only, 0, urlLimit)
		if data.Error != "" || data.DomainDetail == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"status":  "error",
				"message": "domain not found",
			})
			return
		}

		items, count := domainAssetItems(data.DomainDetail, route.kind)
		writeJSON(w, http.StatusOK, dashboard.JSONAssetList{
			Status: "ok",
			Kind:   route.kind,
			Title:  globalAssetTitles[route.kind],
			Count:  count,
			Items:  items,
		})
	}
}

func makeAssetsJSONHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		kind := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/assets/"), "/")
		title, ok := globalListKinds[kind]
		if !ok {
			http.NotFound(w, r)
			return
		}

		list, err := loadGlobalList(deps, kind, title)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "failed to load " + kind,
			})
			return
		}

		items, count := globalAssetItems(list, kind)
		writeJSON(w, http.StatusOK, dashboard.JSONAssetList{
			Status: "ok",
			Kind:   kind,
			Title:  list.Title,
			Count:  count,
			Items:  items,
		})
	}
}

type domainAPIRoute struct {
	domain string
	kind   string
}

func parseDomainAPIPath(path string) (domainAPIRoute, bool) {
	rest := strings.Trim(strings.TrimPrefix(path, "/api/domains/"), "/")
	if rest == "" {
		return domainAPIRoute{}, false
	}
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		return domainAPIRoute{domain: parts[0]}, true
	case 3:
		if parts[1] == "assets" {
			if _, ok := globalAssetTitles[parts[2]]; ok {
				return domainAPIRoute{domain: parts[0], kind: parts[2]}, true
			}
		}
	}
	return domainAPIRoute{}, false
}

func domainAssetItems(detail *dashboard.DomainDetailData, kind string) (any, int) {
	switch kind {
	case "subdomains":
		items := dashboard.SubdomainsJSON(detail.Subdomains)
		return items, len(items)
	case "ports":
		items := dashboard.PortsJSON(detail.Ports)
		return items, len(items)
	case "certificates":
		items := dashboard.CertificatesJSON(detail.Certificates)
		return items, len(items)
	case "technologies":
		items := dashboard.TechnologiesJSON(detail.Technologies)
		return items, len(items)
	case "dns":
		items := dashboard.DNSRecordsJSON(detail.DNSRecords)
		return items, len(items)
	case "vulnerabilities", "findings":
		items := dashboard.FindingsJSON(detail.Findings)
		return items, len(items)
	case "urls":
		items := dashboard.URLsJSON(detail.URLs)
		return items, len(items)
	case "apis":
		items := dashboard.APIsJSON(detail.APIs)
		return items, len(items)
	case "emails":
		items := dashboard.EmailsJSON(detail.Emails)
		return items, len(items)
	case "cloud":
		items := dashboard.CloudStorageJSON(detail.CloudStorage)
		return items, len(items)
	case "takeovers":
		items := dashboard.TakeoversJSON(detail.Takeovers)
		return items, len(items)
	default:
		return []any{}, 0
	}
}

func globalAssetItems(list *dashboard.GlobalListData, kind string) (any, int) {
	switch kind {
	case "subdomains":
		items := dashboard.SubdomainsJSON(list.Subdomains)
		return items, len(items)
	case "ports":
		items := dashboard.PortsJSON(list.Ports)
		return items, len(items)
	case "certificates":
		items := dashboard.CertificatesJSON(list.Certificates)
		return items, len(items)
	case "urls":
		items := dashboard.URLsJSON(list.URLs)
		return items, len(items)
	case "apis":
		items := dashboard.APIsJSON(list.APIs)
		return items, len(items)
	case "emails":
		items := dashboard.EmailsJSON(list.Emails)
		return items, len(items)
	case "cloud":
		items := dashboard.CloudStorageJSON(list.CloudStorage)
		return items, len(items)
	case "findings":
		items := dashboard.FindingsJSON(list.Findings)
		return items, len(items)
	case "takeovers":
		items := dashboard.TakeoversJSON(list.Takeovers)
		return items, len(items)
	default:
		return []any{}, 0
	}
}

func domainStatsFromRows(rows []database.DomainWithStats) []dashboard.DomainStats {
	out := make([]dashboard.DomainStats, len(rows))
	for i, d := range rows {
		out[i] = dashboard.DomainStats{
			ID:             d.ID,
			Domain:         d.Domain,
			AddedAt:        d.AddedAt,
			LastScanned:    d.LastScanned,
			SubdomainCount: d.SubdomainCount,
			PortCount:      d.PortCount,
			CriticalCount:  d.CriticalCount,
			HighCount:      d.HighCount,
		}
	}
	return out
}

func filterDomainStats(domains []dashboard.DomainStats, query url.Values) ([]dashboard.DomainStats, error) {
	searchTerm := strings.TrimSpace(query.Get("q"))
	dateFrom := query.Get("from")
	dateTo := query.Get("to")
	if dateFrom != "" {
		if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
			return nil, fmt.Errorf("invalid from date")
		}
	}
	if dateTo != "" {
		if _, err := time.Parse("2006-01-02", dateTo); err != nil {
			return nil, fmt.Errorf("invalid to date")
		}
	}

	filtered := make([]dashboard.DomainStats, 0, len(domains))
	for _, d := range domains {
		if searchTerm != "" && !strings.Contains(strings.ToLower(d.Domain), strings.ToLower(searchTerm)) {
			continue
		}
		if dateFrom != "" && d.LastScanned != nil {
			fromDate, _ := time.Parse("2006-01-02", dateFrom)
			if d.LastScanned.Before(fromDate) {
				continue
			}
		}
		if dateTo != "" && d.LastScanned != nil {
			toDate, _ := time.Parse("2006-01-02", dateTo)
			if d.LastScanned.After(toDate.Add(24 * time.Hour)) {
				continue
			}
		}
		if (dateFrom != "" || dateTo != "") && d.LastScanned == nil {
			continue
		}
		filtered = append(filtered, d)
	}
	return filtered, nil
}

func wantsJSON(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return true
	}
	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}
