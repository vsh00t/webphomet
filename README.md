# WebPhomet — Autonomous Pentesting Orchestration Platform

WebPhomet is an AI-driven pentesting orchestration platform that leverages an LLM agent (Z.ai) to coordinate security tools through the Model Context Protocol (MCP), automate reconnaissance, vulnerability discovery, exploitation analysis, and report generation — all constrained by strict scope policies.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        WebPhomet                             │
│                                                              │
│  ┌──────────┐   ┌────────────┐   ┌───────────────────────┐  │
│  │  FastAPI  │◄─►│  Z.ai Agent│◄─►│  MCP Gateway          │  │
│  │  Backend  │   │  (LLM)     │   │  (JSON-RPC)           │  │
│  │  :8000    │   └────────────┘   └───────┬───────────────┘  │
│  └─────┬─────┘                            │                  │
│        │                    ┌──────────────┴──────────────┐  │
│        │                    │   MCP CLI-Security Server   │  │
│        │                    │  ┌──────┐ ┌──────┐ ┌─────┐ │  │
│        │                    │  │ nmap │ │nuclei│ │ffuf │ │  │
│  ┌─────┴─────┐              │  │subfndr│httpx │ │dalfx│ │  │
│  │ Celery    │              │  │sqlmap│ │schema│ │kxss │ │  │
│  │ Workers   │              │  └──────┘ └──────┘ └─────┘ │  │
│  └─────┬─────┘              └────────────────────────────┘  │
│        │                                                     │
│  ┌─────┴─────┐  ┌──────────┐                                │
│  │PostgreSQL │  │  Redis   │                                │
│  │  :5432    │  │  :6379   │                                │
│  └───────────┘  └──────────┘                                │
└──────────────────────────────────────────────────────────────┘
         ▲                            │
         │         Scope Validator    │
         │         ────────────────   ▼
    ┌────┴───────────────────────────────────┐
    │  Target Apps (DVWA, Juice Shop, etc.)  │
    └────────────────────────────────────────┘
```

---

## Prerequisites

| Tool             | Version  | Notes                         |
|------------------|----------|-------------------------------|
| Docker           | ≥ 24.0   | With Compose v2 plugin        |
| Docker Compose   | ≥ 2.20   | Bundled with Docker Desktop   |
| Caido Desktop    | Latest   | Running on host at `:8080`    |

---

## Quickstart

```bash
# 1. Clone the repo
git clone <repo-url> webphomet && cd webphomet

# 2. Configure environment
cp .env.example .env
# Edit .env and set your ZAI_API_KEY, CAIDO_API_KEY, etc.

# 3. Launch all services
docker compose up -d

# 4. Verify
curl http://localhost:8000/health
# {"status":"ok"}

# 5. (Optional) Launch vulnerable targets for testing
docker compose -f targets/docker-compose.targets.yml up -d
# DVWA  → http://localhost:4280
# Juice Shop → http://localhost:3000
```

---

## Development Setup

```bash
# Create a virtual environment
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run locally (needs postgres + redis running)
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Project Structure

```
webphomet/
├── backend/          # FastAPI + Celery application
│   ├── src/
│   │   ├── api/      # REST API endpoints
│   │   ├── agent/    # Z.ai LLM agent integration
│   │   ├── core/     # Schemas, logging, scope validation
│   │   ├── db/       # SQLAlchemy models & database config
│   │   ├── jobs/     # Celery tasks & workers
│   │   ├── mcp/      # MCP Gateway + CLI-Security server
│   │   └── reporting/ # Report generation (Jinja2)
│   └── tests/
├── mcp-cli-security/ # Docker image with security tools
├── targets/          # Vulnerable apps for testing
└── ToDo.md           # Roadmap & task tracking
```

---

## Roadmap

See [ToDo.md](ToDo.md) for the full roadmap and task tracking.

---

## License

Private — All rights reserved.
