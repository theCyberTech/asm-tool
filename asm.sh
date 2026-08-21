#!/bin/bash
# ASM Tool - Attack Surface Management
# Go-based CLI wrapper

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_BINARY="$SCRIPT_DIR/asm-go/asm-go"
DB_PATH="$SCRIPT_DIR/asm-go/data/asm.db"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if Go binary exists
check_binary() {
    if [ ! -x "$GO_BINARY" ]; then
        echo -e "${RED}Error: Go binary not found${NC}"
        echo "Build with: cd asm-go && go build -o asm-go ./cmd/asm"
        exit 1
    fi
}

# Run Go binary with database path
run() {
    check_binary
    "$GO_BINARY" --db "$DB_PATH" "$@"
}

print_help() {
    echo "ASM Tool - Attack Surface Management"
    echo ""
    echo "Usage: ./asm.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  status             Show database status"
    echo "  dashboard          Start the web dashboard"
    echo "  scan <domain>      Run a full scan on a domain"
    echo "  discover <domain>  Enumerate subdomains"
    echo "  portscan <domain>  Scan ports on discovered hosts"
    echo "  certificates       Check SSL certificates"
    echo "  dns <domain>       Check DNS records"
    echo "  takeover           Detect subdomain takeover vulnerabilities"
    echo "  fingerprint        Identify technologies"
    echo "  urls <domain>      Enumerate historical URLs"
    echo "  apis               Discover API endpoints"
    echo "  cloudstorage       Detect cloud storage buckets"
    echo "  nuclei             Run Nuclei vulnerability scan"
    echo "  report             Generate a report"
    echo "  diff <domain>      Compare the last two scan snapshots"
    echo "  schedule           View or run scheduled scans"
    echo "  migrate            Run database migrations"
    echo ""
    echo "Examples:"
    echo "  ./asm.sh status"
    echo "  ./asm.sh dashboard"
    echo "  ./asm.sh scan example.com"
    echo "  ./asm.sh discover example.com"
    echo "  ./asm.sh portscan example.com --ports 80,443,8080"
    echo "  ./asm.sh nuclei --all-known --tags cve"
    echo "  ./asm.sh report --format html"
    echo "  ./asm.sh diff example.com"
    echo "  ./asm.sh schedule start"
}

init() {
    echo -e "${GREEN}Initializing ASM Tool...${NC}"

    # Create directories
    mkdir -p asm-go/data reports logs

    # Copy config if not exists
    if [ ! -f config.yaml ]; then
        cp config.example.yaml config.yaml
        echo -e "${YELLOW}Created config.yaml - please edit with your settings${NC}"
    fi

    # Build Go binary if needed
    if [ ! -x "$GO_BINARY" ]; then
        echo -e "${GREEN}Building Go binary...${NC}"
        cd asm-go && go build -o asm-go ./cmd/asm && cd ..
    fi

    echo -e "${GREEN}Initialization complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Edit config.yaml with your domain(s) and API keys"
    echo "2. Run: ./asm.sh scan yourdomain.com"
}

# Main
case "${1:-help}" in
    init)
        init
        ;;
    help|--help|-h)
        print_help
        ;;
    status|dashboard|scan|discover|portscan|ports|certificates|certs|dns|takeover|fingerprint|urls|apis|cloudstorage|cloud|nuclei|report|migrate|diff|schedule)
        cmd="$1"
        shift
        # Normalize command aliases
        case "$cmd" in
            ports) cmd="portscan" ;;
            certs) cmd="certificates" ;;
            cloud) cmd="cloudstorage" ;;
        esac
        run "$cmd" "$@"
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        print_help
        exit 1
        ;;
esac
