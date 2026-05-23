package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/pathsafe"
	"github.com/spf13/cobra"
)

// MigrateCmd creates the migrate command for TinyDB to SQLite migration
func MigrateCmd(deps *Deps) *cobra.Command {
	var (
		tinydbPath string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate data from Python TinyDB to SQLite",
		Long: `Migrate existing data from the Python ASM tool's TinyDB database
to the Go version's SQLite database.

This command reads the TinyDB JSON file and imports all data including:
- Domains and subdomains
- Port scan results
- TLS certificates
- Technologies fingerprints
- DNS records
- URLs and APIs
- Emails
- WHOIS records

Example:
  asm migrate --from data/asm.db
  asm migrate --from ../data/asm.db
  asm migrate --from ../data/asm.db --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tinydbPath == "" {
				// Default to sibling directory
				tinydbPath = "data/asm.db"
			}
			return runMigration(deps.DB, tinydbPath, dryRun)
		},
	}

	cmd.Flags().StringVar(&tinydbPath, "from", "", "Path to TinyDB JSON file (default: data/asm.db)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be migrated without actually migrating")

	return cmd
}

// TinyDB table structures matching Python schema
type tinyDBData struct {
	Domains      map[string]tinyDomain      `json:"domains"`
	Subdomains   map[string]tinySubdomain   `json:"subdomains"`
	Ports        map[string]tinyPort        `json:"ports"`
	Certificates map[string]tinyCertificate `json:"certificates"`
	Technologies map[string]tinyTechnology  `json:"technologies"`
	DNSRecords   map[string]tinyDNSRecord   `json:"dns_records"`
	URLs         map[string]tinyURL         `json:"urls"`
	APIs         map[string]tinyAPI         `json:"apis"`
	Emails       map[string]tinyEmail       `json:"emails"`
	WHOISRecords map[string]tinyWHOIS       `json:"whois_records"`
}

type tinyDomain struct {
	Domain      string `json:"domain"`
	AddedAt     string `json:"added_at"`
	LastScanned string `json:"last_scanned"`
}

type tinySubdomain struct {
	RootDomain   string `json:"root_domain"`
	Subdomain    string `json:"subdomain"`
	DiscoveredAt string `json:"discovered_at"`
	LastSeen     string `json:"last_seen"`
	Active       bool   `json:"active"`
}

type tinyPort struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	DiscoveredAt string `json:"discovered_at"`
	LastSeen     string `json:"last_seen"`
	State        string `json:"state"`
}

type tinyCertificate struct {
	Host            string   `json:"host"`
	Issuer          string   `json:"issuer"`
	Subject         string   `json:"subject"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	SerialNumber    string   `json:"serial_number"`
	Fingerprint     string   `json:"fingerprint"`
	SAN             []string `json:"san"`
	CheckedAt       string   `json:"checked_at"`
}

type tinyTechnology struct {
	Host          string                 `json:"host"`
	StatusCode    int                    `json:"status_code"`
	Title         string                 `json:"title"`
	Technologies  []string               `json:"technologies"`
	Server        string                 `json:"server"`
	Headers       map[string]interface{} `json:"headers"`
	ContentLength int                    `json:"content_length"`
	RedirectURL   string                 `json:"redirect_url"`
	CheckedAt     string                 `json:"checked_at"`
}

type tinyDNSRecord struct {
	Domain    string                 `json:"domain"`
	Records   map[string]interface{} `json:"records"`
	CheckedAt string                 `json:"checked_at"`
}

type tinyURL struct {
	Domain       string `json:"domain"`
	URL          string `json:"url"`
	Interesting  bool   `json:"interesting"`
	DiscoveredAt string `json:"discovered_at"`
	LastSeen     string `json:"last_seen"`
}

type tinyAPI struct {
	URL                   string      `json:"url"`
	Type                  string      `json:"type"`
	Host                  string      `json:"host"`
	Version               string      `json:"version"`
	Title                 string      `json:"title"`
	EndpointsCount        int         `json:"endpoints_count"`
	Endpoints             interface{} `json:"endpoints"`
	IntrospectionEnabled  bool        `json:"introspection_enabled"`
	TypesCount            int         `json:"types_count"`
	Queries               interface{} `json:"queries"`
	Mutations             interface{} `json:"mutations"`
	DiscoveredAt          string      `json:"discovered_at"`
}

type tinyEmail struct {
	Domain       string `json:"domain"`
	Email        string `json:"email"`
	Source       string `json:"source"`
	DiscoveredAt string `json:"discovered_at"`
}

type tinyWHOIS struct {
	Domain            string      `json:"domain"`
	Registrar         string      `json:"registrar"`
	RegistrarURL      interface{} `json:"registrar_url"` // Can be string or []string
	CreationDate      string      `json:"creation_date"`
	ExpirationDate    string      `json:"expiration_date"`
	UpdatedDate       string      `json:"updated_date"`
	DaysUntilExpiry   int         `json:"days_until_expiry"`
	NameServers       []string    `json:"name_servers"`
	Status            []string    `json:"status"`
	DNSSEC            string      `json:"dnssec"`
	RegistrantCountry string      `json:"registrant_country"`
	RegistrantOrg     string      `json:"registrant_org"`
	CheckedAt         string      `json:"checked_at"`
	FirstSeen         string      `json:"first_seen"`
}

func runMigration(db *database.Database, tinydbPath string, dryRun bool) error {
	fmt.Printf("\n%s TinyDB to SQLite Migration\n", titleStyle.Render("[*]"))
	fmt.Println(strings.Repeat("=", 60))

	// Check if TinyDB file exists and is readable under cwd
	if _, err := pathsafe.Stat(tinydbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("TinyDB file not found: %s", tinydbPath)
		}
		return fmt.Errorf("TinyDB file: %w", err)
	}

	fmt.Printf("%s Reading TinyDB from: %s\n", labelStyle.Render("[*]"), tinydbPath)

	// Read TinyDB JSON file (bounded, confined to working directory)
	data, err := pathsafe.ReadFile(tinydbPath, pathsafe.MaxMigrateFileBytes)
	if err != nil {
		return fmt.Errorf("reading TinyDB file: %w", err)
	}

	var tinydb tinyDBData
	if err := json.Unmarshal(data, &tinydb); err != nil {
		return fmt.Errorf("parsing TinyDB JSON: %w", err)
	}

	// Print statistics
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%s TinyDB Contents:\n", labelStyle.Render("[*]"))
	fmt.Printf("  %-20s %d\n", "Domains:", len(tinydb.Domains))
	fmt.Printf("  %-20s %d\n", "Subdomains:", len(tinydb.Subdomains))
	fmt.Printf("  %-20s %d\n", "Ports:", len(tinydb.Ports))
	fmt.Printf("  %-20s %d\n", "Certificates:", len(tinydb.Certificates))
	fmt.Printf("  %-20s %d\n", "Technologies:", len(tinydb.Technologies))
	fmt.Printf("  %-20s %d\n", "DNS Records:", len(tinydb.DNSRecords))
	fmt.Printf("  %-20s %d\n", "URLs:", len(tinydb.URLs))
	fmt.Printf("  %-20s %d\n", "APIs:", len(tinydb.APIs))
	fmt.Printf("  %-20s %d\n", "Emails:", len(tinydb.Emails))
	fmt.Printf("  %-20s %d\n", "WHOIS Records:", len(tinydb.WHOISRecords))

	if dryRun {
		fmt.Printf("\n%s Dry run mode - no changes made\n", lowStyle.Render("[+]"))
		return nil
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%s Migrating data...\n\n", titleStyle.Render("[*]"))

	// Migrate domains first (needed for subdomain foreign keys)
	domainIDs := make(map[string]int64)
	migratedDomains := 0
	for _, d := range tinydb.Domains {
		domain, err := db.Domains.Add(d.Domain)
		if err != nil {
			fmt.Printf("  %s Failed to add domain %s: %v\n", highStyle.Render("[!]"), d.Domain, err)
			continue
		}
		domainIDs[d.Domain] = domain.ID
		migratedDomains++
	}
	fmt.Printf("  %s Domains: %d migrated\n", lowStyle.Render("[+]"), migratedDomains)

	// Migrate subdomains
	migratedSubdomains := 0
	for _, s := range tinydb.Subdomains {
		domainID, ok := domainIDs[s.RootDomain]
		if !ok {
			// Domain doesn't exist yet, create it
			domain, err := db.Domains.Add(s.RootDomain)
			if err != nil {
				continue
			}
			domainID = domain.ID
			domainIDs[s.RootDomain] = domainID
		}
		if err := db.Domains.AddSubdomain(domainID, s.Subdomain); err != nil {
			continue
		}
		migratedSubdomains++
	}
	fmt.Printf("  %s Subdomains: %d migrated\n", lowStyle.Render("[+]"), migratedSubdomains)

	// Migrate ports
	migratedPorts := 0
	for _, p := range tinydb.Ports {
		state := p.State
		if state == "" {
			state = "open"
		}
		port := &database.Port{
			Host:     p.Host,
			Port:     p.Port,
			Protocol: "tcp",
			Service:  p.Service,
			Version:  p.Version,
			State:    state,
		}
		if err := db.Ports.Add(port); err != nil {
			continue
		}
		migratedPorts++
	}
	fmt.Printf("  %s Ports: %d migrated\n", lowStyle.Render("[+]"), migratedPorts)

	// Migrate certificates
	migratedCerts := 0
	for _, c := range tinydb.Certificates {
		notBefore, _ := parseTime(c.NotBefore)
		notAfter, _ := parseTime(c.NotAfter)
		cert := &database.Certificate{
			Host:            c.Host,
			Port:            443,
			Subject:         c.Subject,
			Issuer:          c.Issuer,
			SerialNumber:    c.SerialNumber,
			NotBefore:       notBefore,
			NotAfter:        notAfter,
			DaysUntilExpiry: c.DaysUntilExpiry,
			Fingerprint:     c.Fingerprint,
			SAN:             strings.Join(c.SAN, ", "),
		}
		if err := db.Certificates.Add(cert); err != nil {
			continue
		}
		migratedCerts++
	}
	fmt.Printf("  %s Certificates: %d migrated\n", lowStyle.Render("[+]"), migratedCerts)

	// Migrate technologies
	migratedTechs := 0
	for _, t := range tinydb.Technologies {
		techList, _ := json.Marshal(t.Technologies)
		headerList, _ := json.Marshal(t.Headers)
		err := db.SaveTechnology(t.Host, t.StatusCode, t.Title, t.Server, string(techList), string(headerList), int64(t.ContentLength), t.RedirectURL)
		if err != nil {
			continue
		}
		migratedTechs++
	}
	fmt.Printf("  %s Technologies: %d migrated\n", lowStyle.Render("[+]"), migratedTechs)

	// Migrate DNS records
	migratedDNS := 0
	for _, d := range tinydb.DNSRecords {
		recordsJSON, _ := json.Marshal(d.Records)
		err := db.SaveDNSRecords(d.Domain, string(recordsJSON))
		if err != nil {
			continue
		}
		migratedDNS++
	}
	fmt.Printf("  %s DNS Records: %d migrated\n", lowStyle.Render("[+]"), migratedDNS)

	// Migrate URLs
	migratedURLs := 0
	for _, u := range tinydb.URLs {
		interesting := 0
		if u.Interesting {
			interesting = 1
		}
		err := db.SaveURL(u.Domain, u.URL, "", "", interesting)
		if err != nil {
			continue
		}
		migratedURLs++
	}
	fmt.Printf("  %s URLs: %d migrated\n", lowStyle.Render("[+]"), migratedURLs)

	// Migrate APIs
	migratedAPIs := 0
	for _, a := range tinydb.APIs {
		endpoints, _ := json.Marshal(a.Endpoints)
		introspection := 0
		if a.IntrospectionEnabled {
			introspection = 1
		}
		err := db.SaveAPI(a.URL, a.Type, a.Title, a.Version, a.EndpointsCount, string(endpoints), introspection)
		if err != nil {
			continue
		}
		migratedAPIs++
	}
	fmt.Printf("  %s APIs: %d migrated\n", lowStyle.Render("[+]"), migratedAPIs)

	// Migrate emails
	migratedEmails := 0
	for _, e := range tinydb.Emails {
		err := db.SaveEmail(e.Domain, e.Email, e.Source)
		if err != nil {
			continue
		}
		migratedEmails++
	}
	fmt.Printf("  %s Emails: %d migrated\n", lowStyle.Render("[+]"), migratedEmails)

	// Migrate WHOIS records
	migratedWHOIS := 0
	for _, w := range tinydb.WHOISRecords {
		creationDate, _ := parseTime(w.CreationDate)
		expirationDate, _ := parseTime(w.ExpirationDate)
		updatedDate, _ := parseTime(w.UpdatedDate)
		nameServers := strings.Join(w.NameServers, ", ")
		status := strings.Join(w.Status, ", ")

		// Handle registrar_url which can be string or []string
		var registrarURL string
		switch v := w.RegistrarURL.(type) {
		case string:
			registrarURL = v
		case []interface{}:
			var urls []string
			for _, u := range v {
				if s, ok := u.(string); ok {
					urls = append(urls, s)
				}
			}
			registrarURL = strings.Join(urls, ", ")
		}

		err := db.SaveWHOISRecord(w.Domain, w.Registrar, registrarURL, creationDate, expirationDate,
			updatedDate, w.DaysUntilExpiry, w.RegistrantOrg, w.RegistrantCountry, nameServers, status, w.DNSSEC)
		if err != nil {
			continue
		}
		migratedWHOIS++
	}
	fmt.Printf("  %s WHOIS Records: %d migrated\n", lowStyle.Render("[+]"), migratedWHOIS)

	// Summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("%s Migration complete!\n", lowStyle.Render("[+]"))

	return nil
}

// parseTime attempts to parse various time formats
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse time: %s", s)
}
