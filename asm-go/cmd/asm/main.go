package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/asm-tool/asm-go/internal/cli/commands"
	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	dbPath  string
	deps    = commands.NewDeps()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "asm",
		Short: "ASM - Attack Surface Management Tool",
		Long: `ASM is a high-performance attack surface management tool for security practitioners.
It monitors domains for subdomains, open ports, certificates, technologies,
DNS records, vulnerabilities, URLs, subdomain takeovers, API endpoints, and email addresses.`,
		PersistentPreRunE: initConfig,
		PersistentPostRun: cleanup,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.yaml", "config file path")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "database path (default: data/asm.db)")

	// Add commands
	rootCmd.AddCommand(commands.StatusCmd(deps))
	rootCmd.AddCommand(commands.DiscoverCmd(deps))
	rootCmd.AddCommand(commands.PortscanCmd(deps))
	rootCmd.AddCommand(commands.CertificatesCmd(deps))
	rootCmd.AddCommand(commands.DNSCmd(deps))
	rootCmd.AddCommand(commands.TakeoverCmd(deps))
	rootCmd.AddCommand(commands.FingerprintCmd(deps))
	rootCmd.AddCommand(commands.URLsCmd(deps))
	rootCmd.AddCommand(commands.APIsCmd(deps))
	rootCmd.AddCommand(commands.EmailsCmd(deps))
	rootCmd.AddCommand(commands.CloudStorageCmd(deps))
	rootCmd.AddCommand(commands.ScanCmd(deps))
	rootCmd.AddCommand(commands.ReportCmd(deps))
	rootCmd.AddCommand(commands.NucleiCmd(deps))
	rootCmd.AddCommand(commands.MigrateCmd(deps))
	rootCmd.AddCommand(commands.DashboardCmd(deps))
	rootCmd.AddCommand(commands.DiffCmd(deps))
	rootCmd.AddCommand(commands.ScheduleCmd(deps))
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initConfig(cmd *cobra.Command, args []string) error {
	var err error

	// Load config
	deps.Cfg, err = config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Override database path if specified
	if dbPath != "" {
		deps.Cfg.DatabasePath = dbPath
	}

	// Ensure data directory exists
	dataDir := filepath.Dir(deps.Cfg.DatabasePath)
	if dataDir != "" && dataDir != "." {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("creating data directory: %w", err)
		}
	}

	// Initialize database
	deps.DB, err = database.New(deps.Cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}

	return nil
}

func cleanup(cmd *cobra.Command, args []string) {
	if deps.DB != nil {
		deps.DB.Close()
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ASM Tool v2.0.0 (Go)")
		},
	}
}
