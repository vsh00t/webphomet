# WebPhomet — Security Model & Hardening Guide

---

## Security Architecture Overview

WebPhomet implements **defence in depth** with multiple overlapping security layers:

```
Request → CORS → Rate Limiter → Size Limit → API Key Auth → Safe Mode → Scope Validator → Execution
```

---

## 1. API Key Authentication

When `API_KEY` is set in the environment, all API requests must include the `X-API-Key` header.

**Excluded paths** (no auth required):
- `/health` — Liveness probe
- `/docs`, `/redoc`, `/openapi.json` — API documentation
- WebSocket upgrade requests

**Configuration:**
```bash
# .env
API_KEY=your-secret-api-key-here
```

**Usage:**
```bash
curl -H "X-API-Key: your-secret-api-key-here" http://localhost:8000/api/v1/sessions/
```

If `API_KEY` is empty or unset, authentication is disabled (development mode).

---

## 2. Rate Limiting

In-memory token bucket rate limiter per client IP.

| Parameter | Value |
|-----------|-------|
| Rate | 20 tokens/second |
| Burst | 100 tokens |
| Scope | Per source IP |
| Response | HTTP 429 with `Rate limit exceeded` message |

The rate limiter automatically cleans up stale entries after 5 minutes.

> **Production note:** For multi-worker deployments, replace the in-memory bucket with a Redis-backed rate limiter (e.g., `redis.incr` with TTL).

---

## 3. Request Size Limiting

All requests with `Content-Length` exceeding **10 MB** are rejected with HTTP 413.

---

## 4. Security Response Headers

Every response includes:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Cache-Control` | `no-store` | Prevent response caching |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Restrict browser APIs |

---

## 5. CORS Policy

Restricted to explicit origins:

```python
CORS_ORIGINS = [
    "http://localhost:3000",   # Juice Shop target (or custom frontend)
    "http://localhost:3001",   # React dashboard dev server
    "http://localhost:8000",   # Backend (Swagger UI)
]
```

Override via `CORS_ORIGINS` environment variable (JSON array format).

---

## 6. Safe Mode (Two-Layer)

Safe mode blocks destructive operations at **two enforcement points**:

### Layer 1 — API (`tools.py`)
The `SafeModePolicy.check()` runs before dispatching any tool. Returns HTTP 403 if:
- Tool is in restricted list (`sqlmap`, `dalfox`, `kxss`) and no explicit override
- Arguments contain dangerous patterns (`--os-shell`, `--exploit`, nmap brute/dos scripts, nuclei exploit templates)

### Layer 2 — Agent Executor (`executor.py`)
Same policy applied inside the agent loop. If the LLM attempts a blocked tool call, it receives a JSON error and must choose a different action.

### Rate Limiter
In-memory sliding window: **60 tool invocations per hour per session** (configurable).

---

## 7. Scope Enforcement (Three-Layer)

### Layer 1 — Backend Scope Validator (`core/scope.py`)
Validates targets in tool arguments against the session's scope:
- Allowed hosts (glob patterns)
- Allowed IPs (CIDR ranges)
- Blocked IPs (RFC1918 by default)
- Inspects CLI flags (`-t`, `-u`, `-h`, `--target`, etc.)

### Layer 2 — MCP Server Scope (`mcp-cli-security/scope.py`)
Independent validation before subprocess execution. Same host/IP check but operates at the MCP server level.

### Layer 3 — Command Whitelist
Only pre-registered tool commands are allowed in `CLISecurityServer`. Unknown commands are rejected.

---

## 8. Input Sanitisation

The `sanitize_tool_arg()` utility rejects user-supplied tool arguments containing:
- Shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `!`, `<`, `>`
- Path traversal sequences: `../`, `..\`

Usage in endpoints:
```python
from src.core.security import sanitize_tool_arg

target = sanitize_tool_arg(request.target)  # Raises ValueError if dangerous
```

---

## 9. Secrets Management

| Practice | Implementation |
|----------|---------------|
| No hardcoded secrets | All secrets via env vars / `.env` file |
| `.env` in `.gitignore` | Never committed to VCS |
| `mask_secret()` utility | Masks API keys in logs (shows first 4 chars only) |
| Pydantic Settings | Type-safe, validated on startup |
| `.env.example` provided | Documents required variables without real values |

---

## 10. Container Security

| Measure | Status |
|---------|--------|
| Non-root user in containers | ✅ Via `USER` directive in Dockerfiles |
| Read-only root filesystem | Recommended (add `read_only: true` in compose) |
| No `--privileged` | ✅ Default |
| Health checks | ✅ All 9 services have health checks |
| Network isolation | ✅ Single bridge network (`webphomet-net`) |
| Resource limits | Recommended (add `deploy.resources.limits` in compose) |

---

## 11. Database Security

| Measure | Implementation |
|---------|---------------|
| Parameterised queries | ✅ SQLAlchemy ORM (no raw SQL) |
| Connection pooling | ✅ asyncpg pool via `create_async_engine` |
| Credential rotation | Via `DATABASE_URL` env var |
| Cascade deletes | ✅ Session deletion cascades to all child records |

---

## 12. Threat Model

### In-Scope Threats

| Threat | Mitigation |
|--------|-----------|
| Unauthorized API access | API key authentication |
| DoS via request flooding | Rate limiting (20 req/s per IP) |
| Command injection via tool args | Input sanitisation + safe mode |
| SSRF via tool misconfiguration | Scope enforcement (3 layers) |
| Privilege escalation via destructive tools | Safe mode policy blocks exploitation tools |
| Data exfiltration via logs | `mask_secret()` for sensitive values |
| XSS in dashboard | React auto-escaping + CSP headers |
| Clickjacking | `X-Frame-Options: DENY` |

### Out-of-Scope (Accepted Risk)

| Risk | Rationale |
|------|-----------|
| MCP server compromise | Internal network only, not exposed |
| LLM prompt injection | Z.ai handles this server-side |
| Physical access | Assumed trusted environment |

---

## Hardening Checklist for Production

- [ ] Set `API_KEY` to a strong random value
- [ ] Set `SAFE_MODE=true`
- [ ] Restrict `CORS_ORIGINS` to actual frontend URL
- [ ] Enable TLS termination (nginx/Caddy reverse proxy)
- [ ] Add `read_only: true` to container configs
- [ ] Set `deploy.resources.limits` (CPU/memory) per service
- [ ] Enable PostgreSQL SSL (`?sslmode=require` in `DATABASE_URL`)
- [ ] Rotate `ZAI_API_KEY` and `CAIDO_AUTH_TOKEN` regularly
- [ ] Run `docker compose` with non-root user
- [ ] Enable Docker content trust (`DOCKER_CONTENT_TRUST=1`)
- [ ] Monitor rate limit 429 responses for abuse patterns
- [ ] Set up log aggregation (ELK/Loki) for security event analysis
