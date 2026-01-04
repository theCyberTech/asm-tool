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
    git \
    jq \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Go for additional tools
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz \
    && rm go1.22.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install Go-based reconnaissance tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest

# Update nuclei templates
RUN nuclei -update-templates -silent || true

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for data persistence
RUN mkdir -p /app/data /app/reports /app/logs

# Set entrypoint
ENTRYPOINT ["python", "-m", "asm"]
CMD ["--help"]
