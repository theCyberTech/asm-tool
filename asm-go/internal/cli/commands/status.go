package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// Styles for terminal output
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255"))

	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	highStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208"))

	mediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220"))

	lowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("40"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)
)

// StatusCmd creates the status command
func StatusCmd(db **database.Database, cfg **config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show database statistics and overview",
		Long:  "Display comprehensive statistics about tracked domains, discovered assets, and findings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(*db, *cfg)
		},
	}
}

func runStatus(db *database.Database, cfg *config.Config) error {
	// Get stats
	stats, err := db.GetStats()
	if err != nil {
		return fmt.Errorf("getting stats: %w", err)
	}

	// Get finding severity counts
	findings, _ := db.GetFindingSeverityCounts()

	// Print header
	fmt.Println()
	fmt.Println(titleStyle.Render("ASM Tool - Database Status"))
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println()

	// Asset Overview
	fmt.Println(titleStyle.Render("Asset Overview"))
	fmt.Println()

	assetRows := [][]string{
		{"Domains", fmt.Sprintf("%d", stats.Domains)},
		{"Subdomains", fmt.Sprintf("%d", stats.Subdomains)},
		{"Open Ports", fmt.Sprintf("%d", stats.Ports)},
		{"Certificates", fmt.Sprintf("%d", stats.Certificates)},
		{"URLs", fmt.Sprintf("%d", stats.URLs)},
		{"APIs", fmt.Sprintf("%d", stats.APIs)},
		{"Emails", fmt.Sprintf("%d", stats.Emails)},
		{"Cloud Buckets", fmt.Sprintf("%d", stats.CloudBuckets)},
	}

	for _, row := range assetRows {
		fmt.Printf("  %s %s\n",
			labelStyle.Render(padRight(row[0]+":", 16)),
			valueStyle.Render(row[1]))
	}
	fmt.Println()

	// Findings Summary
	fmt.Println(titleStyle.Render("Findings Summary"))
	fmt.Println()

	totalFindings := findings.Critical + findings.High + findings.Medium + findings.Low + findings.Info
	openTakeovers := stats.Takeovers

	fmt.Printf("  %s %s\n",
		labelStyle.Render(padRight("Open Findings:", 16)),
		valueStyle.Render(fmt.Sprintf("%d", totalFindings)))
	fmt.Printf("  %s %s\n",
		labelStyle.Render(padRight("Open Takeovers:", 16)),
		valueStyle.Render(fmt.Sprintf("%d", openTakeovers)))
	fmt.Println()

	// Severity breakdown
	if totalFindings > 0 {
		fmt.Println("  Severity Breakdown:")
		if findings.Critical > 0 {
			fmt.Printf("    %s %d\n", criticalStyle.Render("Critical:"), findings.Critical)
		}
		if findings.High > 0 {
			fmt.Printf("    %s %d\n", highStyle.Render("High:    "), findings.High)
		}
		if findings.Medium > 0 {
			fmt.Printf("    %s %d\n", mediumStyle.Render("Medium:  "), findings.Medium)
		}
		if findings.Low > 0 {
			fmt.Printf("    %s %d\n", lowStyle.Render("Low:     "), findings.Low)
		}
		if findings.Info > 0 {
			fmt.Printf("    %s %d\n", infoStyle.Render("Info:    "), findings.Info)
		}
		fmt.Println()
	}

	// Risk Score
	riskScore := calculateRiskScore(findings)
	riskLabel := getRiskLabel(riskScore)
	riskStyle := getRiskStyle(riskScore)

	fmt.Println(titleStyle.Render("Risk Assessment"))
	fmt.Println()
	fmt.Printf("  %s %s (%s)\n",
		labelStyle.Render(padRight("Risk Score:", 16)),
		riskStyle.Render(fmt.Sprintf("%d", riskScore)),
		riskStyle.Render(riskLabel))
	fmt.Println()

	// Database info
	fmt.Println(titleStyle.Render("Database"))
	fmt.Println()
	fmt.Printf("  %s %s\n",
		labelStyle.Render(padRight("Path:", 16)),
		valueStyle.Render(cfg.DatabasePath))

	// Check file size
	if info, err := os.Stat(cfg.DatabasePath); err == nil {
		size := formatBytes(info.Size())
		fmt.Printf("  %s %s\n",
			labelStyle.Render(padRight("Size:", 16)),
			valueStyle.Render(size))
	}
	fmt.Println()

	return nil
}

func calculateRiskScore(f *database.FindingSeverityCounts) int {
	return f.Critical*10 + f.High*5 + f.Medium*2 + f.Low*1
}

func getRiskLabel(score int) string {
	switch {
	case score == 0:
		return "Clean"
	case score < 10:
		return "Low"
	case score < 30:
		return "Medium"
	case score < 60:
		return "High"
	default:
		return "Critical"
	}
}

func getRiskStyle(score int) lipgloss.Style {
	switch {
	case score == 0:
		return lowStyle
	case score < 10:
		return lowStyle
	case score < 30:
		return mediumStyle
	case score < 60:
		return highStyle
	default:
		return criticalStyle
	}
}

func padRight(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(" ", length-len(s))
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
