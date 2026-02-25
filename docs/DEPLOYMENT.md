# WebPhomet — Production Deployment Guide

---

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Docker | ≥ 24.0 | With Compose v2 plugin |
| Docker Compose | ≥ 2.20 | Bundled with Docker Desktop |
| Caido Desktop | Latest | Running on host at `:8088` (optional) |
| 4 GB RAM | Minimum | 8 GB recommended |
| 10 GB disk | Minimum | For images, volumes, artifacts |

---

## 1. Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` with production values:

```bash
# ── Database ──
DATABASE_URL=postgresql+asyncpg://webphomet:STRONG_PASSWORD@postgres:5432/webphomet

# ── Redis ──
REDIS_URL=redis://redis:6379/0

# ── Z.ai Agent ──
ZAI_API_KEY=your-zai-api-key
ZAI_MODEL=glm-5

# ── Caido (optional) ──
CAIDO_API_URL=http://host.docker.internal:8088
CAIDO_AUTH_TOKEN=your-caido-token
CAIDO_REFRESH_TOKEN=your-caido-refresh-token

# ── Security ──
API_KEY=generate-a-strong-random-key-here
SAFE_MODE=true
MAX_PARALLELISM=5

# ── CORS ──
CORS_ORIGINS=["https://your-domain.com"]

# ── Logging ──
LOG_LEVEL=WARNING
```

Generate a strong API key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 2. Launch Services

```bash
# Build and start all 9 services
docker compose up -d --build

# Verify all services are healthy
docker compose ps
```

Expected output:
```
NAME                  STATUS          PORTS
webphomet-postgres    Up (healthy)    5432/tcp
webphomet-redis       Up (healthy)    6379/tcp
webphomet-backend     Up (healthy)    0.0.0.0:8000->8000/tcp
webphomet-celery      Up (healthy)    
webphomet-mcp-cli     Up (healthy)    0.0.0.0:9100->9100/tcp
webphomet-mcp-caido   Up (healthy)    0.0.0.0:9200->9200/tcp
webphomet-mcp-devt    Up (healthy)    0.0.0.0:9300->9300/tcp
webphomet-mcp-git     Up (healthy)    0.0.0.0:9400->9400/tcp
webphomet-frontend    Up (healthy)    0.0.0.0:3001->80/tcp
```

---

## 3. Health Checks

```bash
# Backend API
curl http://localhost:8000/health
# → {"status":"ok"}

# MCP servers
curl http://localhost:9100/health
curl http://localhost:9200/health
curl http://localhost:9300/health
curl http://localhost:9400/health

# Frontend
curl -s http://localhost:3001/ | head -1
```

---

## 4. TLS Termination (Recommended)

Use a reverse proxy for HTTPS. Example with Caddy:

```Caddyfile
webphomet.example.com {
    handle /api/* {
        reverse_proxy backend:8000
    }
    handle /health {
        reverse_proxy backend:8000
    }
    handle {
        reverse_proxy frontend:80
    }
}
```

Or with nginx:
```nginx
server {
    listen 443 ssl;
    server_name webphomet.example.com;

    ssl_certificate /etc/ssl/certs/webphomet.pem;
    ssl_certificate_key /etc/ssl/private/webphomet.key;

    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        proxy_pass http://frontend:80;
    }
}
```

---

## 5. Resource Limits

Add to `docker-compose.yml` for each service:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          memory: 512M
  
  celery-worker:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 2G
  
  postgres:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
```

---

## 6. Scaling Celery Workers

For higher throughput, scale Celery workers:

```bash
docker compose up -d --scale celery-worker=4
```

Ensure Redis can handle the connection count:
```bash
# redis.conf
maxclients 1000
```

---

## 7. Database Backups

### Automated daily backup

```bash
#!/bin/bash
# scripts/backup-db.sh
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
docker compose exec -T postgres pg_dump -U webphomet webphomet \
  | gzip > backups/webphomet_${TIMESTAMP}.sql.gz

# Keep last 30 days
find backups/ -name "*.sql.gz" -mtime +30 -delete
```

Add to crontab:
```
0 3 * * * /path/to/webphomet/scripts/backup-db.sh
```

### Restore

```bash
gunzip -c backups/webphomet_20260224_030000.sql.gz \
  | docker compose exec -T postgres psql -U webphomet webphomet
```

---

## 8. Log Management

WebPhomet outputs structured JSON logs. Pipe to your log aggregation system:

```yaml
# docker-compose.yml
services:
  backend:
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"
```

For ELK/Loki integration, use Filebeat or Promtail pointed at Docker log files.

---

## 9. Data Retention

Configure automatic purge of old sessions:

```bash
# Purge sessions older than 30 days
curl -X POST http://localhost:8000/api/v1/admin/purge \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 30}'
```

---

## 10. Monitoring

### Prometheus metrics (recommended add-on)

Add a `/metrics` endpoint or use a sidecar exporter. Key metrics to watch:

| Metric | Alert Threshold |
|--------|----------------|
| HTTP 5xx rate | > 1% of requests |
| HTTP 429 rate | > 10% of requests |
| Celery queue depth | > 50 pending tasks |
| PostgreSQL connections | > 80% of max |
| Redis memory usage | > 80% of maxmemory |
| Container restart count | > 0 in 1 hour |

### Health check monitoring

```bash
# Simple cron-based monitor
*/5 * * * * curl -sf http://localhost:8000/health || echo "WebPhomet DOWN" | mail -s "ALERT" admin@example.com
```

---

## 11. Vulnerable Targets (Testing Only)

For testing, launch the bundled vulnerable applications:

```bash
docker compose -f targets/docker-compose.targets.yml up -d
```

| Target | Port | Description |
|--------|------|-------------|
| DVWA | 4280 | Damn Vulnerable Web Application |
| Juice Shop | 3000 | OWASP Juice Shop |

> **Warning:** Never expose vulnerable targets to the internet.

---

## 12. Upgrading

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose up -d --build

# Run database migrations (if any)
# Migrations are auto-applied on startup via create_all()
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Backend won't start | Check `DATABASE_URL` and `REDIS_URL` connectivity |
| MCP connection failed | Verify MCP containers are healthy: `docker compose logs mcp-cli-security` |
| Celery tasks stuck | Check Redis: `docker compose exec redis redis-cli llen celery` |
| 429 Too Many Requests | Rate limit reached — wait or increase burst in `security.py` |
| 401 Unauthorized | Verify `X-API-Key` header matches `API_KEY` env var |
| Frontend can't reach API | Check nginx proxy config in `frontend/nginx.conf` |
| Database full | Run `POST /api/v1/admin/purge` with appropriate `retention_days` |
