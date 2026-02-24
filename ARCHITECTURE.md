# WebPhomet — Architecture Reference

> Última actualización: 24 Feb 2026

---

## Visión general

WebPhomet es una plataforma de pentesting autónomo orquestada por IA (Z.ai GLM-4.5/4.6).
La arquitectura sigue un modelo de **orquestador central + workers + MCP servers**:

```
┌──────────────────────────────────────────────────────────────┐
│                        Usuario / API                         │
│                   POST /api/v1/agent/start                   │
└───────────────────────────┬──────────────────────────────────┘
                            │
                ┌───────────▼───────────┐
                │   Backend (FastAPI)   │  ← puerto 8000
                │   + API REST          │
                │   + Pydantic schemas  │
                │   + SafeModePolicy    │
                └───────────┬───────────┘
                            │ Celery task dispatch
                ┌───────────▼───────────┐
                │   Celery Worker       │
                │   jobs.run_tool       │
                │   jobs.run_agent      │
                │   jobs.build_report   │
                └───────────┬───────────┘
                            │ JSON-RPC 2.0
                ┌───────────▼───────────┐
                │  MCP CLI-Security     │  ← puerto 9100
                │  (nmap, subfinder,    │
                │   httpx, whatweb,     │
                │   nuclei, ffuf, etc.) │
                └───────────────────────┘
```

**Flujo de datos**: API → Celery → MCP → stdout/stderr → Parsers → Persistence → DB

---

## Servicios Docker

| Servicio | Puerto | Imagen | Healthcheck |
|----------|--------|--------|-------------|
| `postgres` | 5432 | `postgres:16-alpine` | `pg_isready -U webphomet` |
| `redis` | 6379 | `redis:7-alpine` | `redis-cli ping` |
| `backend` | 8000 | `python:3.12-slim` (custom) | `curl http://localhost:8000/health` |
| `celery-worker` | — | misma imagen que backend | — |
| `mcp-cli-security` | 9100 | `python:3.12-slim` + Go tools (custom) | `curl http://localhost:9100/health` |

Red compartida: `webphomet-net` (bridge).  
Volúmenes: `postgres-data`, `redis-data`, `artifacts` (compartido backend↔celery↔mcp).

---

## Mapa de archivos

### Raíz del proyecto

| Archivo | Descripción |
|---------|-------------|
| `docker-compose.yml` | Orquestación de 5 servicios con healthchecks |
| `docker-compose.targets.yml` (`targets/`) | DVWA (4280) + Juice Shop (3000) para pruebas |
| `.env` / `.env.example` | Variables de entorno (DB, Redis, Z.ai API key, MCP URL, SAFE_MODE) |
| `ToDo.md` | Plan de desarrollo con 3 horizontes y estado de cada tarea |
| `README.md` | Quickstart y requisitos |
| `reqs.txt` | Especificación arquitectónica original |

### `mcp-cli-security/` — Servidor MCP de herramientas de seguridad

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `app.py` (194 líneas) | FastAPI JSON-RPC server: `/health`, `/rpc`, `/` | 1.3.1 |
| `server.py` (159 líneas) | `CLISecurityServer.run_command()`: whitelist, scope check, `asyncio.create_subprocess_exec`, timeout 600s | 1.3.1, 1.3.5 |
| `scope.py` (176 líneas) | `ScopeValidator`: allowed_hosts, allowed_ips (CIDR), blocked_ips, target extraction heurísticos | 1.3.2 |
| `Dockerfile` | `python:3.12-slim` + Go 1.22.5, instala nmap/whatweb (apt), subfinder/httpx/nuclei/ffuf/dalfox/kxss (go install), sqlmap/schemathesis (pip) | 1.1.3 |

### `backend/src/` — Backend orquestador

#### `main.py` — Entry point

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `main.py` (80 líneas) | FastAPI app, lifespan (create tables on startup, dispose engine on shutdown), CORS, `/health`, monta `api_router` en `/api/v1` | 1.1.4 |
| `config.py` (53 líneas) | Pydantic `Settings` desde env vars: `DATABASE_URL`, `REDIS_URL`, `ZAI_API_KEY`, `ZAI_MODEL`, `CAIDO_API_URL`, `MCP_CLI_SECURITY_URL`, `SAFE_MODE`, `MAX_PARALLELISM`, `LOG_LEVEL`, `CORS_ORIGINS` | 1.1.7 |

#### `api/` — Endpoints REST

| Archivo | Endpoints | Tarea |
|---------|-----------|-------|
| `router.py` | Agrega sub-routers bajo `/api/v1` | — |
| `sessions.py` | `POST /sessions`, `GET /sessions`, `GET /sessions/{id}`, `DELETE /sessions/{id}` | 1.2.1 |
| `findings.py` | `POST /findings`, `GET /findings/session/{id}`, `GET /findings/session/{id}/summary` | 1.2.3 |
| `tools.py` | `POST /tools/run` (single tool + safe mode), `POST /tools/recon` (parallel sweep), `GET /tools/session/{id}`, `GET /tools/{id}`, `GET /tools/task/{id}/status` | 1.2.2, 1.4.6 |
| `agent.py` | `POST /agent/start`, `GET /agent/status/{task_id}`, `POST /agent/stop/{task_id}` | 1.4.5 |

#### `db/` — Capa de datos

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `database.py` (62 líneas) | `create_async_engine`, `async_sessionmaker`, `get_db` (dependency) | 1.1.5 |
| `models.py` (234 líneas) | ORM: `PentestSession`, `Target`, `Finding`, `Artifact`, `ToolRun` con enums (`Severity`, `FindingStatus`, `RunStatus`, `SessionStatus`), relationships, columnas JSON | 1.1.5 |
| `dal.py` (413 líneas) | CRUD completo: `create_session`, `get_session` (eager load), `list_sessions`, `upsert_target` (merge ports/tech por host), `create_finding`, `get_findings` (filtered), `get_findings_summary`, `create_tool_run`, `start_tool_run`, `complete_tool_run`, `get_tool_runs`, `create_artifact`, `get_artifacts` | 1.2.3 |
| `persistence.py` (254 líneas) | Puente tool output → parsers → DB. `persist_tool_result()`: completa ToolRun, almacena raw artifact, parsea output, almacena parsed artifact, extrae entidades (targets de nmap/subfinder/httpx/whatweb, findings de nuclei) | 1.3.4 |

#### `parsers/` — Parseadores de output de herramientas

| Archivo | Formato de entrada | Estructuras de salida | Tarea |
|---------|--------------------|-----------------------|-------|
| `nmap.py` (278 líneas) | XML (`-oX`) + texto plano (fallback) | `NmapResult` → `NmapHost` → `NmapService` | 1.3.3 |
| `subfinder.py` (~140 líneas) | JSON lines + texto plano | `SubfinderResult` → lista de subdominios | 1.3.3 |
| `httpx.py` (~170 líneas) | JSON lines | `HttpxResult` → `HttpxEntry` (url, status, title, tech, content_length) | 1.3.3 |
| `whatweb.py` (~230 líneas) | JSON + texto plano | `WhatWebResult` → `WhatWebEntry` (target, plugins/technologies) | 1.3.3 |
| `nuclei.py` (~220 líneas) | JSON lines | `NucleiResult` → `NucleiMatch` + `.to_finding_dict()` para auto-crear Findings | 1.3.3 |
| `dispatch.py` (~90 líneas) | — | `parse_tool_output()`: dispatcher universal, `has_parser()`, `UNPARSED_TOOLS` | 1.3.3 |

Todos los parsers implementan `.to_dict()` y `.to_summary()`. Nuclei adicional: `.to_finding_dict()` con mapeo severidad → `Finding` schema.

#### `agent/` — Capa de agente autónomo (Z.ai)

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `client.py` (96 líneas) | `ZaiClient`: wrapper async httpx para `https://open.bigmodel.cn/api/paas/v4/chat/completions`. Soporta `tools` (function calling), `tool_choice: auto`, temperature, max_tokens | 1.4.1 |
| `tools.py` (217 líneas) | 9 tool definitions OpenAI-compatible: `create_pentest_session`, `get_session_state`, `run_recon`, `get_recon_results`, `parse_nmap_output`, `summarize_findings`, `correlate_findings`, `build_report`, `export_report` | 1.4.2, 1.4.3, 1.4.4 |
| `executor.py` (333 líneas) | Registry `@register(name)` + `dispatch(name, args, db)`. Implementaciones reales de cada tool: crea sesiones, consulta estado, despacha Celery tasks, polling de resultados, correlación heurística de findings, despacho de reportes | 1.4.2–1.4.4 |
| `orchestrator.py` (374 líneas) | `AgentOrchestrator.run()`: loop plan→execute→evaluate. Max 30 iteraciones, system prompt con contexto de sesión, async polling de tool runs (5s interval, max 120 polls = 10min), detección de terminación por keywords, `_finalize_session()` marca COMPLETED | 1.4.5 |

#### `core/` — Módulos transversales

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `schemas.py` (171 líneas) | Pydantic schemas: `EndpointDescriptor`, `FindingCreate/Response`, `SessionCreate/Response`, `ToolRunCreate/Response`, enums espejo de DB | — |
| `scope.py` (136 líneas) | `ScopeValidator` backend-side: `validate_target()` (host patterns, IP/CIDR), `validate_command()` (inspecciona flags `-t`, `-u`, `-h`, etc.) | 1.3.2 |
| `safe_mode.py` (218 líneas) | `SafeModePolicy.check()`: bloquea tools destructivos (`sqlmap`, `dalfox`, `kxss`), patrones de args peligrosos (--os-shell, --exploit, nmap scripts brute/dos/fuzzer, nuclei exploit templates), rate limiter in-memory (60/hr/session). Retorna `PolicyResult` con `.enforce()` | 1.4.6 |
| `logging.py` | Structured JSON logging con `python-json-logger` | 1.2.5 |

#### `jobs/` — Celery tasks

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `celery_app.py` (28 líneas) | Configuración Celery: broker/backend Redis, JSON serialization, `acks_late`, `prefetch_multiplier=1`, autodiscover `src.jobs` | 1.1.6 |
| `workers.py` (310 líneas) | 3 tasks: `jobs.run_tool` (MCP call → persist), `jobs.run_agent` (lanza orchestrator loop), `jobs.build_report` (carga desde DB → Jinja2 render → MD + PDF → artifacts) | 1.2.2, 1.4.5, 1.5.1 |

#### `mcp/` — MCP Gateway

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `gateway.py` (100 líneas) | `MCPGateway`: dataclass con `server_urls` dict, `call(server, method, params)` construye JSON-RPC 2.0 envelope, POST a `/rpc`, manejo de errores. `list_tools()` helper. Timeout 300s | 1.2.4 |

#### `reporting/` — Generación de reportes

| Archivo | Descripción | Tarea |
|---------|-------------|-------|
| `builder.py` (255 líneas) | `ReportBuilder`: `render_markdown()`, `render_html()`, `generate_pdf()` (weasyprint primary), `markdown_to_pdf()` (pandoc fallback). CSS inline en fallback HTML | 1.5.1, 1.5.4 |
| `templates/report.md.j2` (148 líneas) | Plantilla Markdown: portada, resumen ejecutivo con tabla severidades, scope, targets, tools, risk matrix, findings iterados, anexos | 1.5.2 |
| `templates/report.html.j2` (~230 líneas) | Plantilla HTML con CSS embebido: severity badges coloreados, finding cards con page-break-inside:avoid, tablas styled | 1.5.2 |

---

## Endpoints API completos

Base: `http://localhost:8000/api/v1`

### Sessions

| Método | Path | Descripción | Request body |
|--------|------|-------------|-------------|
| `POST` | `/sessions` | Crear sesión | `{ target_base_url, app_type?, scope?, config? }` |
| `GET` | `/sessions` | Listar sesiones | — |
| `GET` | `/sessions/{id}` | Detalle sesión | — |
| `DELETE` | `/sessions/{id}` | Eliminar sesión | — |

### Findings

| Método | Path | Descripción | Params |
|--------|------|-------------|--------|
| `POST` | `/findings` | Crear finding | `{ session_id, vuln_type, title, severity, ... }` |
| `GET` | `/findings/session/{id}` | Listar findings | `?severity=&status=` |
| `GET` | `/findings/session/{id}/summary` | Resumen estadístico | — |

### Tools

| Método | Path | Descripción | Request body |
|--------|------|-------------|-------------|
| `POST` | `/tools/run` | Ejecutar tool (async) | `{ session_id, tool_name, args }` |
| `POST` | `/tools/recon` | Sweep recon paralelo | `{ session_id, target, tools?, nmap_args?, ... }` |
| `GET` | `/tools/session/{id}` | Listar runs por sesión | `?tool_name=` |
| `GET` | `/tools/{tool_run_id}` | Detalle de un run | — |
| `GET` | `/tools/task/{task_id}/status` | Status de task Celery | — |

### Agent

| Método | Path | Descripción | Request body |
|--------|------|-------------|-------------|
| `POST` | `/agent/start` | Iniciar agente autónomo | `{ session_id, max_iterations?, model? }` |
| `GET` | `/agent/status/{task_id}` | Status del agente | — |
| `POST` | `/agent/stop/{task_id}` | Detener agente (revoke) | — |

### Health

| Método | Path | Descripción |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |

Swagger UI auto-generado: `http://localhost:8000/docs`

---

## Decisiones de diseño

### 1. Celery sync → asyncio bridge (`_run_async`)
Celery tasks son síncronas por diseño. Se usa `asyncio.new_event_loop()` para ejecutar coroutines (MCP calls, DB persistence) desde el contexto sync del worker. Cada task crea y destruye su propio loop.

### 2. `upsert_target` merge strategy
Cuando múltiples herramientas descubren el mismo host, `upsert_target()` hace merge de `ports` y `technologies` dicts en vez de sobrescribir. Esto permite que nmap agregue puertos y whatweb agregue tecnologías al mismo target.

### 3. Nuclei → Finding automático
El parser de nuclei implementa `.to_finding_dict()` que convierte matches directamente al schema `Finding` del DB, mapeando severidad nuclei → severidad WebPhomet. Esto permite auto-creación de findings sin intervención del agente.

### 4. Safe mode en dos capas
La política se aplica tanto en la API (`tools.py` → `SafeModePolicy.check().enforce()` → HTTP 403) como en el agent executor (`executor.py` → retorna error JSON al LLM). Doble barrera: si el agente intenta algo destructivo, se bloquea antes de llegar a Celery.

### 5. PDF generation: weasyprint primary, pandoc fallback
- **weasyprint**: no requiere LaTeX, buena calidad, funciona bien en containers
- **pandoc + xelatex**: mejor tipografía pero requiere texlive (~2GB), solo se usa si está disponible
- **Fallback último**: si ninguno está disponible, se guarda HTML

### 6. Agent reasoning loop: 30 iterations, 5s poll
- Max 30 plan→execute cycles previene agentes runaway
- Polling cada 5s × max 120 intentos (10min) para tools async
- Detección de terminación por keywords ("pentest complete", "report generated")
- Si el LLM emite text sin tool_calls ni keywords de terminación, se le da un nudge automático

### 7. Rate limiting in-memory
El rate limiter usa sliding window (60 invocaciones/hr/sesión) en memoria Python. Es suficiente para single-instance; en producción multi-worker se necesitaría Redis-backed.

### 8. Scope validation multicapa
1. **MCP CLI-Security** (`scope.py`): valida antes de ejecutar el proceso
2. **Backend** (`core/scope.py`): valida targets en argumentos de comandos
3. **Safe mode** (`core/safe_mode.py`): bloquea categorías completas de herramientas/args

---

## Modelo de datos (PostgreSQL)

```
┌─────────────────┐       ┌────────────────┐
│ pentest_sessions │──1:N──│    targets     │
│                  │       └────────────────┘
│  id (UUID PK)   │       ┌────────────────┐
│  target_base_url │──1:N──│   findings     │
│  app_type        │       └────────────────┘
│  scope (JSONB)   │       ┌────────────────┐
│  config (JSONB)  │──1:N──│   tool_runs    │──1:N──┐
│  status (enum)   │       └────────────────┘       │
│  created_at      │       ┌────────────────┐       │
│  updated_at      │──1:N──│   artifacts    │◄──────┘
└─────────────────┘       └────────────────┘
```

### Enums

| Enum | Valores |
|------|---------|
| `SessionStatus` | `created`, `running`, `paused`, `completed`, `failed` |
| `RunStatus` | `pending`, `running`, `success`, `failed`, `cancelled` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `FindingStatus` | `open`, `confirmed`, `false_positive`, `fixed` |

---

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://webphomet:webphomet@postgres:5432/webphomet` | Connection string PostgreSQL |
| `REDIS_URL` | `redis://redis:6379/0` | Broker/backend Celery |
| `ZAI_API_KEY` | `""` | API key de Z.ai (ZhipuAI) |
| `ZAI_MODEL` | `glm-4.5` | Modelo a usar (`glm-4.5` o `glm-4.6`) |
| `CAIDO_API_URL` | `http://host.docker.internal:8080` | URL API de Caido Desktop (H2) |
| `CAIDO_API_KEY` | `""` | API key de Caido (H2) |
| `MCP_CLI_SECURITY_URL` | `http://mcp-cli-security:9100` | URL del servidor MCP CLI-Security |
| `SAFE_MODE` | `true` | Bloquea herramientas/args destructivos |
| `MAX_PARALLELISM` | `5` | Máximo de tools concurrentes |
| `LOG_LEVEL` | `INFO` | Nivel de logging |
| `CORS_ORIGINS` | `["http://localhost:3000", "http://localhost:8000"]` | Orígenes CORS permitidos |
