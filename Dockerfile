# =============================================================================
# Stage 1: Build Go tools
# =============================================================================
FROM golang:1.22-alpine AS go-builder

# Install git for go install
RUN apk add --no-cache git

# Set Go environment
ENV CGO_ENABLED=0
ENV GOPATH=/go
ENV PATH="/go/bin:${PATH}"

# Install Go-based reconnaissance tools with pinned versions
# Versions pinned for reproducible builds - update periodically
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8 && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.4 && \
    go install -v github.com/tomnomnom/assetfinder@v0.1.1 && \
    go install -v github.com/lc/gau/v2/cmd/gau@v2.2.3

# =============================================================================
# Stage 2: Runtime image
# =============================================================================
FROM python:3.11-slim

LABEL maintainer="Security Team"
LABEL description="Attack Surface Management Tool"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    jq \
    chromium \
    chromium-driver \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/

# Create non-root user for security
RUN groupadd --gid 1000 asm && \
    useradd --uid 1000 --gid asm --shell /bin/bash --create-home asm

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for data persistence and set ownership
RUN mkdir -p /app/data /app/reports /app/logs && \
    chown -R asm:asm /app

# Update nuclei templates (as asm user)
USER asm
RUN nuclei -update-templates -silent || true

# Health check - verify the tool can run
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m asm --help > /dev/null 2>&1 || exit 1

# Set entrypoint
ENTRYPOINT ["python", "-m", "asm"]
CMD ["--help"]
