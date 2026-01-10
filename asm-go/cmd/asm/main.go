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
	cfg     *config.Config
	db      *database.Database
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
	rootCmd.AddCommand(commands.StatusCmd(&db, &cfg))
	rootCmd.AddCommand(commands.DiscoverCmd(&db, &cfg))
	rootCmd.AddCommand(commands.PortscanCmd(&db, &cfg))
	rootCmd.AddCommand(commands.CertificatesCmd(&db, &cfg))
	rootCmd.AddCommand(commands.DNSCmd(&db, &cfg))
	rootCmd.AddCommand(commands.TakeoverCmd(&db, &cfg))
	rootCmd.AddCommand(commands.FingerprintCmd(&db, &cfg))
	rootCmd.AddCommand(commands.URLsCmd(&db, &cfg))
	rootCmd.AddCommand(commands.APIsCmd(&db, &cfg))
	rootCmd.AddCommand(commands.EmailsCmd(&db, &cfg))
	rootCmd.AddCommand(commands.CloudStorageCmd(&db, &cfg))
	rootCmd.AddCommand(commands.ScanCmd(&db, &cfg))
	rootCmd.AddCommand(commands.ReportCmd(&db, &cfg))
	rootCmd.AddCommand(commands.NucleiCmd(&db, &cfg))
	rootCmd.AddCommand(commands.MigrateCmd(&db, &cfg))
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initConfig(cmd *cobra.Command, args []string) error {
	var err error

	// Load config
	cfg, err = config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Override database path if specified
	if dbPath != "" {
		cfg.DatabasePath = dbPath
	}

	// Ensure data directory exists
	dataDir := filepath.Dir(cfg.DatabasePath)
	if dataDir != "" && dataDir != "." {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("creating data directory: %w", err)
		}
	}

	// Initialize database
	db, err = database.New(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}

	return nil
}

func cleanup(cmd *cobra.Command, args []string) {
	if db != nil {
		db.Close()
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
