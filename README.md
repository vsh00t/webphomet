# WebPhomet — Autonomous Pentesting Orchestration Platform

WebPhomet is an AI-driven pentesting orchestration platform that leverages an LLM agent (Z.ai) to coordinate security tools through the Model Context Protocol (MCP), automate reconnaissance, vulnerability discovery, exploitation analysis, and report generation — all constrained by strict scope policies.

**9 Docker services** · **46 tools** · **16 Celery task types** · **8 breakpoint phases** · **WebSocket real-time** · **48 tests**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           WebPhomet v0.3                            │
│                                                                     │
│  ┌──────────┐   ┌────────────┐   ┌──────────────────────────────┐  │
│  │  React   │   │  FastAPI   │◄─►│  Z.ai Agent (LLM)           │  │
│  │Dashboard ├──►│  Backend   │   │  46 tools · 16 Celery tasks  │  │
│  │  :3001   │ws │  :8000     │   └──────────┬───────────────────┘  │
│  └──────────┘   └──────┬─────┘              │ MCP Gateway          │
│                        │            ┌───────┴──────┬───────┬─────┐ │
│                  ┌─────┴─────┐   ┌──┴───┐  ┌──┴──┐│┌─┴──┐│┌┴───┐│ │
│                  │  Celery   │   │CLI   │  │Caido││ DevT││ Git ││ │
│                  │  Workers  │   │:9100 │  │:9200││:9300││:9400││ │
│                  └─────┬─────┘   └──────┘  └─────┘└─────┘└─────┘│ │
│                  ┌─────┴─────┐  ┌──────┐                         │ │
│                  │PostgreSQL │  │Redis │                         │ │
│                  │  :5432    │  │:6379 │                         │ │
│                  └───────────┘  └──────┘                         │ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| **LLM Agent** | Z.ai (GLM-5) autonomous agent with ReAct loop, tool calling, and planning |
| **MCP Gateway** | JSON-RPC 2.0 proxy to 4 MCP servers (CLI-Security, Caido, DevTools, Git/Code) |
| **46 Security Tools** | Nmap, Nuclei, SQLMap, ffuf, Dalfox, httpx, Subfinder, Schemathesis + custom |
| **Code-Aware Scanning** | Git repo cloning, source code analysis, 7 vuln categories, 50+ regex patterns |
| **Mobile Testing** | Caido proxy integration, traffic analysis, sensitive data detection |
| **Interactive Breakpoints** | 8 configurable phases, per-tool/severity breaks, auto-approve timeout |
| **React Dashboard** | Real-time session monitoring, findings table, breakpoint approval UI |
| **Scope Enforcement** | Whitelist hosts/IPs, block RFC1918, validate all tool commands |
| **Data Retention** | Configurable purge policy (RETENTION_DAYS), artifact file cleanup |
| **Security Hardened** | Non-root containers, safe mode, parallelism limits |
| **OWASP Mapping** | Findings mapped to OWASP Top 10 with CVSS scoring |
| **Report Generation** | HTML/PDF reports with executive summary, findings, evidence, PoC |

---

## Prerequisites

| Tool             | Version  | Notes                         |
|------------------|----------|-------------------------------|
| Docker           | ≥ 24.0   | With Compose v2 plugin        |
| Docker Compose   | ≥ 2.20   | Bundled with Docker Desktop   |
| Caido Desktop    | Latest   | Running on host at `:8088`    |

---

## Quickstart

```bash
# 1. Clone the repo
git clone https://github.com/vsh00t/webphomet.git && cd webphomet

# 2. Configure environment
cp .env.example .env
# Edit .env: set ZAI_API_KEY, CAIDO tokens, etc.

# 3. Launch all services (9 containers)
docker compose up -d --build

# 4. Verify
curl http://localhost:8000/health        # Backend API
curl http://localhost:3001/              # React Dashboard
curl http://localhost:9100/health        # CLI-Security MCP
curl http://localhost:9400/health        # Git/Code MCP

# 5. Open the dashboard
open http://localhost:3001

# 6. (Optional) Launch vulnerable targets
docker compose -f targets/docker-compose.targets.yml up -d
# DVWA → http://localhost:4280   |   Juice Shop → http://localhost:3000
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| `frontend` | 3001 | React dashboard (nginx + API/WS proxy) |
| `backend` | 8000 | FastAPI REST API + agent orchestrator |
| `celery-worker` | — | Async task execution (4 concurrent) |
| `mcp-cli-security` | 9100 | Nmap, Nuclei, SQLMap, ffuf, Dalfox, httpx, etc. |
| `mcp-caido` | 9200 | Caido GraphQL proxy |
| `mcp-devtools` | 9300 | Headless Chrome (Playwright) |
| `mcp-git-code` | 9400 | Git repo + source code analysis |
| `postgres` | 5432 | PostgreSQL 16 |
| `redis` | 6379 | Redis 7 (Celery broker) |

---

## API Reference

### Sessions
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sessions/` | Create pentest session |
| GET | `/api/v1/sessions/` | List all sessions |
| GET | `/api/v1/sessions/{id}` | Get session details |
| PATCH | `/api/v1/sessions/{id}` | Update session |

### Findings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/findings/?session_id={id}` | List findings |
| POST | `/api/v1/findings/` | Create finding |

### Agent
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agent/run` | Launch autonomous agent |
| GET | `/api/v1/agent/status/{session_id}` | Agent status |

### Tools (12 endpoints)
`/api/v1/tools/{clone-repo,code-audit,search-code,find-hotspots,git-log,git-diff,git-blame,git-tree,git-file,list-repos,analyze-mobile-traffic}`

### Breakpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/breakpoints/configure` | Set breakpoint config |
| GET | `/api/v1/breakpoints/config/{id}` | Get config |
| GET | `/api/v1/breakpoints/pending` | List pending |
| POST | `/api/v1/breakpoints/resolve` | Approve/reject |
| GET | `/api/v1/breakpoints/phases` | List 8 phases |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/stats` | Data size statistics |
| POST | `/api/v1/admin/purge` | Purge old sessions |

### WebSocket
- `WS /api/v1/ws/{session_id}` — Per-session real-time events
- `WS /api/v1/ws` — Global broadcast

---

## Breakpoint Phases

| Phase | Default | Description |
|-------|---------|-------------|
| `pre_recon` | off | Before reconnaissance |
| `post_recon` | **on** | After recon (review targets) |
| `pre_scanning` | off | Before vulnerability scanning |
| `post_scanning` | off | After scanning |
| `pre_exploit` | **on** | Before exploitation attempts |
| `post_exploit` | off | After exploitation |
| `pre_report` | off | Before report generation |
| `post_owasp` | **on** | After OWASP classification |

---

## Development

```bash
# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn src.main:app --reload --port 8000

# Frontend
cd frontend
npm install && npm run dev    # http://localhost:3001

# Tests (48 tests)
cd backend && pytest tests/ -v
```

---

## Project Structure

```
webphomet/
├── backend/                  # FastAPI + Celery
│   ├── src/
│   │   ├── api/              # REST: sessions, findings, tools, agent, breakpoints, admin
│   │   ├── agent/            # LLM orchestrator, 46 tools, executor
│   │   ├── core/             # Breakpoints, WS manager, retention, logging
│   │   ├── db/               # SQLAlchemy models (5 tables)
│   │   ├── jobs/             # 16 Celery tasks, MCP gateway
│   │   └── reporting/        # HTML/PDF (Jinja2 + WeasyPrint)
│   └── tests/                # 48 pytest tests (7 modules)
├── frontend/                 # React 18 + TypeScript + Tailwind
│   ├── src/{pages,components,hooks,lib,types}/
│   ├── Dockerfile            # Multi-stage node→nginx
│   └── nginx.conf            # SPA + API/WS proxy
├── mcp-cli-security/         # Security tools MCP (nmap, nuclei, sqlmap...)
├── mcp-caido/                # Caido GraphQL MCP
├── mcp-devtools/             # Headless Chrome MCP (Playwright)
├── mcp-git-code/             # Git/Code analysis MCP
├── docs/                     # Mobile setup guide
├── scripts/                  # CA cert installer
├── targets/                  # Vulnerable apps (DVWA, Juice Shop)
├── docker-compose.yml        # 9-service orchestration
└── .env                      # Environment secrets
```

---

## Testing

| Module | Tests | Scope |
|--------|-------|-------|
| test_api.py | 12 | REST endpoints (sessions, findings, admin, breakpoints) |
| test_breakpoints.py | 9 | Breakpoint state machine, config, resolution |
| test_tools.py | 6 | Tool definitions structure, uniqueness |
| test_code_analyzer.py | 8 | SINK_PATTERNS regex, categories |
| test_scope.py | 8 | Scope validator (hosts, IPs, commands) |
| test_config.py | 2 | Settings defaults and fields |
| test_ws_manager.py | 2 | WebSocket connection manager |
| test_health.py | 1 | Health endpoint |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL async connection string |
| `REDIS_URL` | Yes | — | Redis connection string |
| `ZAI_API_KEY` | Yes | — | Z.ai API key |
| `ZAI_MODEL` | No | `glm-5` | LLM model |
| `CAIDO_API_URL` | No | `http://host.docker.internal:8088` | Caido proxy URL |
| `CAIDO_AUTH_TOKEN` | No | — | Caido auth token |
| `SAFE_MODE` | No | `true` | Restrict destructive operations |
| `MAX_PARALLELISM` | No | `5` | Max concurrent tasks |
| `RETENTION_DAYS` | No | `30` | Auto-purge threshold |
| `CORS_ORIGINS` | No | `localhost:3000,8000` | Allowed CORS origins |

---

## License

Private — All rights reserved.
