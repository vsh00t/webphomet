# ──────────────────────────────────────────────────────────────
# MCP CLI-Security — Docker image with security tools
# ──────────────────────────────────────────────────────────────
# Tools included:
#   apt   → nmap, whatweb
#   Go    → subfinder, httpx, nuclei, ffuf, dalfox, kxss
#   pip   → sqlmap, schemathesis
# ──────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/usr/local/go \
    PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

# ── System packages ──────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        whatweb \
        wget \
        curl \
        git \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Go (needed to build Go-based tools) ─────────────────────
ARG GO_VERSION=1.22.5
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# ── Go security tools ───────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/tomnomnom/hacks/kxss@latest && \
    cp /usr/local/go/bin/* /usr/local/bin/ 2>/dev/null || true && \
    cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# ── Python security tools ───────────────────────────────────
RUN pip install --no-cache-dir \
        sqlmap \
        schemathesis \
        fastapi \
        uvicorn[standard] \
        pydantic

# ── Nuclei templates update ─────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Copy application files ─────────────────────────────────────
# Create directory structure
RUN mkdir -p /app/src/mcp/cli_security

# Copy Python application files
COPY app.py /app/
COPY scope.py /app/
COPY server.py /app/
COPY site_mirror.py /app/
COPY secret_scanner.py /app/

# ── Artifacts directory ──────────────────────────────────────
RUN mkdir -p /app/artifacts

# ── Non-root user ────────────────────────────────────────────
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser && \
    chown -R appuser:appuser /app
USER appuser

# ── Run FastAPI server ─────────────────────────────────────
EXPOSE 9100
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9100", "--log-level", "info"]
