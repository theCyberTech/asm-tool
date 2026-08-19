package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/config"
	"github.com/theCyberTech/asm-tool/asm-go/internal/database"
	"github.com/theCyberTech/asm-tool/asm-go/internal/target"
	"github.com/spf13/cobra"
)

// DiffCmd creates the diff command for comparing scan snapshots
func DiffCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "diff <domain>",
		Short: "Show changes between the last two scans",
		Long: `Compare the two most recent scan snapshots for a domain and report:
- New and closed subdomains
- New and closed ports
- New and resolved vulnerabilities

Requires at least two prior scans (run 'asm scan' twice first).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(deps.DB, deps.Cfg, args[0])
		},
	}
}

func runDiff(db *database.Database, cfg *config.Config, domain string) error {
	domain, err := target.NormalizeTarget(domain)
	if err != nil {
		return err
	}

	snapshots, err := db.GetLatestSnapshots(domain, 2)
	if err != nil {
		return err
	}
	if len(snapshots) < 2 {
		return fmt.Errorf("need at least 2 scans for %s to diff (have %d). Run 'asm scan %s' first", domain, len(snapshots), domain)
	}

	// snapshots[0] = newest, snapshots[1] = previous
	current := snapshots[0]
	previous := snapshots[1]

	printDiffHeader(domain, previous, current)

	changes := false

	// Subdomain diff
	if diff := diffSubdomains(previous.Subdomains, current.Subdomains); diff != nil {
		printSubdomainDiff(diff)
		changes = true
	}

	// Port diff
	if diff := diffPorts(previous.Ports, current.Ports); diff != nil {
		printPortDiff(diff)
		changes = true
	}

	// Vulnerability diff
	if diff := diffVulns(previous.Vulnerabilities, current.Vulnerabilities); diff != nil {
		printVulnDiff(diff)
		changes = true
	}

	if !changes {
		fmt.Printf("  %s No changes detected between scans.\n", lowStyle.Render("[=]"))
	}

	fmt.Println(strings.Repeat("=", 60))
	return nil
}

// ── Header ──────────────────────────────────────────────────────────────────

func printDiffHeader(domain string, previous, current database.Snapshot) {
	fmt.Printf("\n%s Scan Diff: %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Previous:", 20)),
		previous.Timestamp.Format(time.RFC3339))
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Current:", 20)),
		current.Timestamp.Format(time.RFC3339))
	fmt.Println(strings.Repeat("-", 60))
}

// ── Subdomain diff ──────────────────────────────────────────────────────────

func diffSubdomains(prevJSON, currJSON string) *subdomainDiff {
	var prev, curr []string
	json.Unmarshal([]byte(prevJSON), &prev)
	json.Unmarshal([]byte(currJSON), &curr)

	prevSet := make(map[string]bool)
	for _, s := range prev {
		prevSet[s] = true
	}
	currSet := make(map[string]bool)
	for _, s := range curr {
		currSet[s] = true
	}

	var added, removed []string
	for _, s := range curr {
		if !prevSet[s] {
			added = append(added, s)
		}
	}
	for _, s := range prev {
		if !currSet[s] {
			removed = append(removed, s)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	sort.Strings(added)
	sort.Strings(removed)
	return &subdomainDiff{Added: added, Removed: removed, PrevCount: len(prev), CurrCount: len(curr)}
}

type subdomainDiff struct {
	Added     []string
	Removed   []string
	PrevCount int
	CurrCount int
}

func printSubdomainDiff(d *subdomainDiff) {
	fmt.Printf("\n%s Subdomains (%d -> %d)\n", titleStyle.Render("[*]"), d.PrevCount, d.CurrCount)
	for _, s := range d.Added {
		fmt.Printf("  %s %s\n", lowStyle.Render("[+]"), s)
	}
	for _, s := range d.Removed {
		fmt.Printf("  %s %s\n", highStyle.Render("[-]"), s)
	}
}

// ── Port diff ───────────────────────────────────────────────────────────────

type portEntry struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"`
}

func portKey(p portEntry) string {
	return fmt.Sprintf("%s:%d/%s", p.Host, p.Port, p.Service)
}

type portDiff struct {
	Added   []portEntry
	Removed []portEntry
	PrevLen int
	CurrLen int
}

func diffPorts(prevJSON, currJSON string) *portDiff {
	var prev, curr []portEntry
	json.Unmarshal([]byte(prevJSON), &prev)
	json.Unmarshal([]byte(currJSON), &curr)

	prevMap := make(map[string]portEntry)
	for _, p := range prev {
		prevMap[portKey(p)] = p
	}
	currMap := make(map[string]portEntry)
	for _, p := range curr {
		currMap[portKey(p)] = p
	}

	var added, removed []portEntry
	for k, p := range currMap {
		if _, ok := prevMap[k]; !ok {
			added = append(added, p)
		}
	}
	for k, p := range prevMap {
		if _, ok := currMap[k]; !ok {
			removed = append(removed, p)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	sort.Slice(added, func(i, j int) bool {
		return portKey(added[i]) < portKey(added[j])
	})
	sort.Slice(removed, func(i, j int) bool {
		return portKey(removed[i]) < portKey(removed[j])
	})
	return &portDiff{Added: added, Removed: removed, PrevLen: len(prev), CurrLen: len(curr)}
}

func printPortDiff(d *portDiff) {
	fmt.Printf("\n%s Open Ports (%d -> %d)\n", titleStyle.Render("[*]"), d.PrevLen, d.CurrLen)
	for _, p := range d.Added {
		svc := p.Service
		if svc == "" {
			svc = "unknown"
		}
		fmt.Printf("  %s %s:%d (%s)\n", lowStyle.Render("[+]"), p.Host, p.Port, svc)
	}
	for _, p := range d.Removed {
		svc := p.Service
		if svc == "" {
			svc = "unknown"
		}
		fmt.Printf("  %s %s:%d (%s)\n", highStyle.Render("[-]"), p.Host, p.Port, svc)
	}
}

// ── Vulnerability diff ──────────────────────────────────────────────────────

type vulnEntry struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
}

func vulnKey(v vulnEntry) string {
	return fmt.Sprintf("%s@%s", v.TemplateID, v.Host)
}

type vulnDiff struct {
	Added   []vulnEntry
	Removed []vulnEntry
}

func diffVulns(prevJSON, currJSON string) *vulnDiff {
	var prev, curr []vulnEntry
	json.Unmarshal([]byte(prevJSON), &prev)
	json.Unmarshal([]byte(currJSON), &curr)

	prevMap := make(map[string]vulnEntry)
	for _, v := range prev {
		prevMap[vulnKey(v)] = v
	}
	currMap := make(map[string]vulnEntry)
	for _, v := range curr {
		currMap[vulnKey(v)] = v
	}

	var added, removed []vulnEntry
	for k, v := range currMap {
		if _, ok := prevMap[k]; !ok {
			added = append(added, v)
		}
	}
	for k, v := range prevMap {
		if _, ok := currMap[k]; !ok {
			removed = append(removed, v)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	// Sort by severity then name
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(added, func(i, j int) bool {
		if sevOrder[added[i].Severity] != sevOrder[added[j].Severity] {
			return sevOrder[added[i].Severity] < sevOrder[added[j].Severity]
		}
		return added[i].Name < added[j].Name
	})
	sort.Slice(removed, func(i, j int) bool {
		if sevOrder[removed[i].Severity] != sevOrder[removed[j].Severity] {
			return sevOrder[removed[i].Severity] < sevOrder[removed[j].Severity]
		}
		return removed[i].Name < removed[j].Name
	})
	return &vulnDiff{Added: added, Removed: removed}
}

func severityStyle(sev string) string {
	switch sev {
	case "critical":
		return criticalStyle.Render("CRITICAL")
	case "high":
		return highStyle.Render("HIGH")
	case "medium":
		return mediumStyle.Render("MEDIUM")
	case "low":
		return lowStyle.Render("LOW")
	default:
		return infoStyle.Render("INFO")
	}
}

func printVulnDiff(d *vulnDiff) {
	fmt.Printf("\n%s Vulnerabilities\n", titleStyle.Render("[*]"))
	for _, v := range d.Added {
		fmt.Printf("  %s [%s] %s @ %s\n", criticalStyle.Render("[+]"),
			severityStyle(v.Severity), v.Name, v.Host)
	}
	for _, v := range d.Removed {
		fmt.Printf("  %s [%s] %s @ %s\n", lowStyle.Render("[-]"),
			severityStyle(v.Severity), v.Name, v.Host)
	}
}
