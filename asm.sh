#!/bin/bash
# ASM Tool Helper Script
# Simplifies common operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_help() {
    echo "ASM Tool - Attack Surface Management"
    echo ""
    echo "Usage: ./asm.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build         Build the Docker image"
    echo "  shell         Start an interactive shell in the container"
    echo "  scan <domain> Run a full scan on a domain"
    echo "  discover <domain>  Enumerate subdomains"
    echo "  ports <domain>     Scan ports on discovered hosts"
    echo "  certs <domain>     Check SSL certificates"
    echo "  urls <domain>      Enumerate historical URLs (Wayback, CommonCrawl)"
    echo "  takeover           Detect subdomain takeover vulnerabilities"
    echo "  apis               Discover API endpoints (Swagger, OpenAPI, GraphQL)"
    echo "  emails             Enumerate email addresses"
    echo "  vulns <domain>     Run vulnerability scan"
    echo "  report             Generate a report"
    echo "  status             Show database status"
    echo "  trends <domain>    Show historical trend analysis"
    echo "  trends <domain>    Show historical trend analysis"
    echo "  trends <domain>    Show historical trend analysis"
    echo "  update             Update nuclei templates"
    echo "  clean              Remove containers and volumes"
    echo ""
    echo "Examples:"
    echo "  ./asm.sh build"
    echo "  ./asm.sh scan example.com"
    echo "  ./asm.sh discover example.com"
    echo "  ./asm.sh shell"
}

build() {
    echo -e "${GREEN}Building ASM Tool Docker image...${NC}"
    docker build -t asm-tool .
}

run_cmd() {
    docker run --rm -it \
        -v "$SCRIPT_DIR/data:/app/data" \
        -v "$SCRIPT_DIR/reports:/app/reports" \
        -v "$SCRIPT_DIR/config.yaml:/app/config.yaml:ro" \
        --network host \
        asm-tool "$@"
}

shell() {
    echo -e "${GREEN}Starting interactive shell...${NC}"
    docker run --rm -it \
        -v "$SCRIPT_DIR/data:/app/data" \
        -v "$SCRIPT_DIR/reports:/app/reports" \
        -v "$SCRIPT_DIR/config.yaml:/app/config.yaml:ro" \
        --network host \
        --entrypoint /bin/bash \
        asm-tool
}

scan() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Domain required${NC}"
        echo "Usage: ./asm.sh scan <domain>"
        exit 1
    fi
    echo -e "${GREEN}Running full scan on $1...${NC}"
    run_cmd scan "$1"
}

discover() {
    echo -e "${GREEN}Discovering subdomains...${NC}"
    run_cmd discover "$@"
}

ports() {
    echo -e "${GREEN}Scanning ports...${NC}"
    run_cmd portscan "$@"
}

certs() {
    echo -e "${GREEN}Checking certificates...${NC}"
    run_cmd certificates "$@"
}

urls() {
    echo -e "${GREEN}Enumerating historical URLs...${NC}"
    run_cmd urls "$@"
}

takeover() {
    echo -e "${GREEN}Checking for subdomain takeover vulnerabilities...${NC}"
    run_cmd takeover "$@"
}

apis() {
    echo -e "${GREEN}Discovering API endpoints...${NC}"
    run_cmd apis "$@"
}

emails() {
    echo -e "${GREEN}Enumerating email addresses...${NC}"
    run_cmd emails "$@"
}

vulns() {
    echo -e "${GREEN}Running vulnerability scan...${NC}"
    run_cmd vulnscan "$@"
}

report() {
    FORMAT="${1:-markdown}"
    OUTPUT="reports/asm-report-$(date +%Y%m%d-%H%M%S).md"
    echo -e "${GREEN}Generating report...${NC}"
    run_cmd report --format "$FORMAT" --output "/app/$OUTPUT"
    echo -e "${GREEN}Report saved to $OUTPUT${NC}"
}

status() {
    run_cmd status
}

update() {
    echo -e "${GREEN}Updating nuclei templates...${NC}"
    docker run --rm -it \
        --entrypoint nuclei \
        asm-tool -update-templates
}

    clean() {
        echo -e "${YELLOW}Removing containers...${NC}"
        docker rm -f asm-tool asm-scheduler 2>/dev/null || true
        echo -e "${GREEN}Done${NC}"
    }

    trends() {
        if [ -z "$1" ]; then
            echo -e "${RED}Error: Domain required${NC}"
            echo -e "Usage: ./asm.sh trends <domain> [options]"
            echo -e ""
            echo -e "Options:"
            echo -e "  --days N              Show trends over the last N days"
            echo -e "  --type, -t            Asset type to analyze (subdomains|ports|certificates|vulnerabilities|all)"
            echo -e "  --format, -f              Output format (table|json|ascii)"
            echo -e "  --alert-threshold       Alert threshold (critical|high|medium)"
            echo -e ""
            exit 1
        fi
        echo -e "${GREEN}Showing trends for $1...${NC}"
        run_cmd trends "$@"
    }

init() {
    echo -e "${GREEN}Initializing ASM Tool...${NC}"
    
    # Create directories
    mkdir -p data reports logs
    
    # Copy config if not exists
    if [ ! -f config.yaml ]; then
        cp config.example.yaml config.yaml
        echo -e "${YELLOW}Created config.yaml - please edit with your settings${NC}"
    fi
    
    # Build image
    build
    
    echo -e "${GREEN}Initialization complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Edit config.yaml with your domain(s) and notification settings"
    echo "2. Run: ./asm.sh scan yourdomain.com"
}

# Main
case "${1:-help}" in
    build)
        build
        ;;
    shell)
        shell
        ;;
    scan)
        scan "$2"
        ;;
    discover)
        shift
        discover "$@"
        ;;
    ports)
        shift
        ports "$@"
        ;;
    certs)
        shift
        certs "$@"
        ;;
    urls)
        shift
        urls "$@"
        ;;
    takeover)
        shift
        takeover "$@"
        ;;
    apis)
        shift
        apis "$@"
        ;;
    emails)
        shift
        emails "$@"
        ;;
    vulns)
        shift
        vulns "$@"
        ;;
    trends)
        shift
        trends "$@"
        ;;
    report)
        report "$2"
        ;;
    status)
        status
        ;;
    update)
        update
        ;;
    clean)
        clean
        ;;
    init)
        init
        ;;
    help|--help|-h)
        print_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        print_help
        exit 1
        ;;
esac
