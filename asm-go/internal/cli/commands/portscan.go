package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/persistence"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/spf13/cobra"
)

// PortscanCmd creates the portscan command
func PortscanCmd(deps *Deps) *cobra.Command {
	var (
		allKnown   bool
		portSpec   string
		workers    int
		timeout    int
		top100     bool
		grabBanner bool
	)

	cmd := &cobra.Command{
		Use:   "portscan [domain|host]",
		Short: "Scan for open ports",
		Long: `Perform high-speed port scanning on targets using native Go TCP connections.

This scanner uses a goroutine pool for massive parallelism, achieving speeds
up to 20x faster than traditional nmap for connect scans.

By default, scans subdomains discovered for the specified domain.
Use --ports to specify custom ports, or --top100 for the top 100 ports.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse ports
			var scanPorts []int
			if top100 {
				scanPorts = ports.Top100Ports()
			} else if portSpec != "" {
				scanPorts = config.ParsePortString(portSpec)
			} else {
				scanPorts = deps.Cfg.ParsePorts()
			}

			if len(scanPorts) == 0 {
				return fmt.Errorf("no ports specified")
			}

			hosts, err := resolveScanHosts(deps.DB, args, allKnown)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				fmt.Println("No hosts to scan")
				return nil
			}

			return runPortscan(deps.DB, hosts, scanPorts, workers, time.Duration(timeout)*time.Second, grabBanner)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Scan all known subdomains")
	cmd.Flags().StringVarP(&portSpec, "ports", "p", "", "Ports to scan (e.g., '80,443,8080' or '1-1000')")
	cmd.Flags().BoolVar(&top100, "top100", false, "Scan top 100 common ports")
	cmd.Flags().IntVarP(&workers, "workers", "w", 500, "Number of concurrent connections")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 2, "Connection timeout in seconds")
	cmd.Flags().BoolVar(&grabBanner, "banner", true, "Attempt to grab service banners")

	return cmd
}

func runPortscan(db *database.Database, hosts []string, scanPorts []int, workers int, timeout time.Duration, grabBanner bool) error {
	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	scanner := ports.NewScanner(workers, timeout)
	scanner.GrabBanner = grabBanner

	fmt.Printf("\n%s Port Scanning %d hosts on %d ports\n",
		titleStyle.Render("[*]"),
		len(hosts),
		len(scanPorts))
	fmt.Printf("%s Workers: %d, Timeout: %s\n",
		labelStyle.Render("   "),
		workers,
		timeout)
	fmt.Println(strings.Repeat("-", 50))

	start := time.Now()
	totalOpen := 0
	var scanResults []*ports.Result

	// For single host, scan directly
	if len(hosts) == 1 {
		result := scanner.Scan(ctx, hosts[0], scanPorts)
		scanResults = []*ports.Result{result}
		printPortResult(result)
		totalOpen = len(result.OpenPorts)
	} else {
		// Batch scan
		results := scanner.ScanBatch(ctx, hosts, scanPorts)
		scanResults = results

		for _, result := range results {
			if len(result.OpenPorts) > 0 {
				printPortResult(result)
				totalOpen += len(result.OpenPorts)
			}
		}
	}

	saved, err := persistence.SavePortScanResults(db, scanResults)
	if err != nil {
		return err
	}

	duration := time.Since(start)
	portsPerSec := float64(len(hosts)*len(scanPorts)) / duration.Seconds()

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s Scan complete: %d open ports found\n",
		titleStyle.Render("[+]"),
		totalOpen)
	fmt.Printf("%s Duration: %s (%.0f ports/sec)\n",
		labelStyle.Render("   "),
		duration.Round(time.Millisecond),
		portsPerSec)
	fmt.Printf("%s Saved %d open ports to database\n", lowStyle.Render("[+]"), saved)

	return nil
}

func printPortResult(result *ports.Result) {
	if result.Error != "" {
		fmt.Printf("\n%s %s: %s\n",
			highStyle.Render("[!]"),
			result.Host,
			result.Error)
		return
	}

	if len(result.OpenPorts) == 0 {
		return
	}

	fmt.Printf("\n%s %s (%d open)\n",
		lowStyle.Render("[+]"),
		valueStyle.Render(result.Host),
		len(result.OpenPorts))

	for _, p := range result.OpenPorts {
		portInfo := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		serviceInfo := p.Service
		if p.Version != "" {
			serviceInfo = fmt.Sprintf("%s (%s)", p.Service, p.Version)
		}

		fmt.Printf("    %s %s\n",
			labelStyle.Render(padRight(portInfo, 12)),
			serviceInfo)

		if p.Banner != "" && len(p.Banner) < 80 {
			fmt.Printf("    %s %s\n",
				labelStyle.Render(padRight("", 12)),
				infoStyle.Render(p.Banner))
		}
	}
}
