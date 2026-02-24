# WebPhomet — Changelog

> Registro detallado de implementación, organizado por sesión y ping.

---

## Sesión 1 — Scaffolding inicial (24 Feb 2026)

**Objetivo**: Crear plan de desarrollo + estructura base del proyecto.

### Acciones

- Creado `ToDo.md` con plan de 30 semanas, 3 horizontes, 6 fases + QA gates
- Scaffolding de ~40 archivos: monorepo con `backend/`, `mcp-cli-security/`, `targets/`
- Archivos creados:
  - `docker-compose.yml` — 5 servicios (postgres, redis, backend, celery-worker, mcp-cli-security)
  - `backend/Dockerfile`, `mcp-cli-security/Dockerfile`
  - `backend/pyproject.toml` — dependencias Python
  - `backend/src/main.py` — FastAPI app entry point
  - `backend/src/config.py` — Pydantic settings
  - `backend/src/db/database.py` — async engine + session factory
  - `backend/src/db/models.py` — 5 tablas ORM (sessions, targets, findings, artifacts, tool_runs)
  - `backend/src/api/sessions.py` — CRUD de sesiones
  - `backend/src/api/router.py` — aggregator de sub-routers
  - `backend/src/core/schemas.py` — Pydantic request/response schemas
  - `backend/src/core/scope.py` — ScopeValidator backend-side
  - `backend/src/core/logging.py` — JSON structured logging
  - `backend/src/mcp/gateway.py` — MCPGateway JSON-RPC 2.0 client
  - `backend/src/jobs/celery_app.py` — Celery configuration
  - `backend/src/jobs/workers.py` — Celery tasks (run_tool, build_report)
  - `backend/src/agent/client.py` — ZaiClient wrapper
  - `backend/src/agent/tools.py` — 9 tool definitions para Z.ai
  - `backend/src/reporting/builder.py` — ReportBuilder (Jinja2)
  - `backend/src/reporting/templates/report.md.j2` — Markdown report template
  - `.env.example`, `README.md`, `targets/docker-compose.targets.yml`
  - Todos los `__init__.py` necesarios

---

## Sesión 2 — Cambios manuales del usuario (24 Feb 2026)

**Autor**: Jorge (manual)

### Acciones

- Implementó `mcp-cli-security/app.py` — FastAPI JSON-RPC server completo (194 líneas)
- Implementó `mcp-cli-security/server.py` — CLISecurityServer con whitelist y subprocess (159 líneas)
- Implementó `mcp-cli-security/scope.py` — ScopeValidator para MCP (176 líneas)
- Conectó Backend ↔ Celery ↔ MCP CLI-Security via JSON-RPC
- Actualizó `docker-compose.yml` con healthchecks funcionales
- Verificó comunicación end-to-end: API → Celery → MCP → tool output

---

## Sesión 3 — Implementación Horizonte 1 (24 Feb 2026)

**Objetivo**: Implementar toda la lógica de negocio restante del Horizonte 1.

### Ping 1 — Parsers + DAL + Persistence + Findings API

**Archivos creados:**

| Archivo | Líneas | Descripción | Tarea |
|---------|--------|-------------|-------|
| `backend/src/parsers/__init__.py` | — | Package init | — |
| `backend/src/parsers/nmap.py` | ~278 | Parser nmap XML + texto: `NmapResult` → `NmapHost` → `NmapService` | 1.3.3 |
| `backend/src/parsers/subfinder.py` | ~140 | Parser subfinder JSON lines + texto: `SubfinderResult` | 1.3.3 |
| `backend/src/parsers/httpx.py` | ~170 | Parser httpx JSON lines: `HttpxResult` → `HttpxEntry` | 1.3.3 |
| `backend/src/parsers/whatweb.py` | ~230 | Parser whatweb JSON + texto: `WhatWebResult` → `WhatWebEntry` | 1.3.3 |
| `backend/src/parsers/nuclei.py` | ~220 | Parser nuclei JSON lines: `NucleiResult` + auto finding extraction via `.to_finding_dict()` | 1.3.3 |
| `backend/src/parsers/dispatch.py` | ~90 | Dispatcher universal: `parse_tool_output()`, `has_parser()`, `UNPARSED_TOOLS` | 1.3.3 |
| `backend/src/db/dal.py` | ~413 | CRUD completo para 5 modelos: sessions, targets, findings, tool_runs, artifacts. Incluye `upsert_target` (merge), `get_findings_summary`, eager loading | 1.2.3 |
| `backend/src/db/persistence.py` | ~254 | `persist_tool_result()`: completa ToolRun → almacena raw artifact → parsea → almacena parsed artifact → extrae targets y findings a DB | 1.3.4 |
| `backend/src/api/findings.py` | ~80 | CRUD de findings: POST create, GET list (filtered), GET summary | 1.2.3 |

**Archivos modificados:**

| Archivo | Cambio | Tarea |
|---------|--------|-------|
| `backend/src/jobs/workers.py` | Reescritura completa: `run_tool` ahora acepta `tool_run_id`, llama a MCP, persiste via `_persist_result` → `persistence.persist_tool_result`. `build_report` carga datos reales del DB | 1.2.2, 1.3.4 |

**Decisiones de diseño:**
- Workers usan `asyncio.new_event_loop()` para bridge sync Celery → async MCP/DB
- `upsert_target` hace merge de dicts `ports` y `technologies` en vez de sobrescribir
- Nuclei matches se convierten automáticamente a Finding schema

### Ping 2 — Tools/Recon API + Router update

**Archivos creados:**

| Archivo | Líneas | Descripción | Tarea |
|---------|--------|-------------|-------|
| `backend/src/api/tools.py` | ~236 | `POST /tools/run` (single tool + safe mode check), `POST /tools/recon` (parallel sweep subfinder+nmap+httpx+whatweb), `GET /tools/session/{id}`, `GET /tools/{id}`, `GET /tools/task/{id}/status` | 1.2.2 |

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `backend/src/api/router.py` | Agregados `findings_router` y `tools_router` |

### Ping 3 — Agent reasoning loop

**Archivos creados:**

| Archivo | Líneas | Descripción | Tarea |
|---------|--------|-------------|-------|
| `backend/src/agent/executor.py` | ~333 | Registry de dispatch con `@register(name)`. Implementa las 9 tools: `_create_session`, `_get_session_state`, `_run_recon` (con safe mode check), `_get_recon_results` (trunca stdout a 8KB), `_summarize_findings`, `_correlate_findings` (heurística de attack chains), `_build_report`, `_export_report` | 1.4.2–1.4.4 |
| `backend/src/agent/orchestrator.py` | ~374 | `AgentOrchestrator.run()`: initialize (load session, build system prompt) → step loop (LLM call → tool dispatch → result feed). Max 30 iterations, poll pending runs (5s × 120 = 10min max), keyword termination detection, auto-nudge si LLM para sin tools ni terminación | 1.4.5 |
| `backend/src/api/agent.py` | ~100 | `POST /agent/start` (valida sesión, despacha `jobs.run_agent`), `GET /agent/status/{task_id}`, `POST /agent/stop/{task_id}` (revoke task) | 1.4.5 |

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `backend/src/jobs/workers.py` | Agregado task `jobs.run_agent` que importa y ejecuta `run_agent_sync()` |
| `backend/src/api/router.py` | Agregado `agent_router` |

**Decisiones de diseño:**
- El orchestrator es stateless entre invocaciones — todo estado en DB + message history
- System prompt incluye session_id, target, scope, safe_mode
- Detección de terminación por keywords en el texto del LLM ("pentest complete", "report generated", etc.)
- Si el LLM emite texto sin tool_calls, se le envía un nudge automático para que use tools o genere reporte

### Ping 4 — Safe mode policy

**Archivos creados:**

| Archivo | Líneas | Descripción | Tarea |
|---------|--------|-------------|-------|
| `backend/src/core/safe_mode.py` | ~218 | `SafeModePolicy.check()`: 6 checks secuenciales: (1) scope, (2) blocked tools (`sqlmap`, `dalfox`, `kxss`), (3) blocked arg patterns (11 regexes: `--os-shell`, `--exploit`, `--dump`, `--brute`, `--dos`, `script=.*exploit`, etc.), (4) nmap script category block (exploit, brute, dos, fuzzer), (5) nuclei exploit template block, (6) rate limit (sliding window, 60/hr/session in-memory). Retorna `PolicyResult` con `.enforce()` que lanza `PolicyViolation` | 1.4.6 |

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `backend/src/api/tools.py` | Agregado `SafeModePolicy` check antes de crear ToolRun — lanza HTTP 403 en violación |
| `backend/src/agent/executor.py` | Agregado policy check en `_run_recon` — retorna error JSON al LLM si viola política |

**Decisiones de diseño:**
- Safe mode aplica en dos capas: API (HTTP 403) + agent executor (error JSON al LLM)
- Rate limiter in-memory es suficiente para single-instance; en producción necesitaría Redis
- Scope check se delega a `ScopeValidator` existente (si está configurado)

### Ping 5 — PDF report generation

**Archivos creados:**

| Archivo | Líneas | Descripción | Tarea |
|---------|--------|-------------|-------|
| `backend/src/reporting/templates/report.html.j2` | ~230 | Plantilla HTML con CSS embebido: severity badges coloreados (`.badge-critical` rojo, `.badge-high` naranja, etc.), finding cards con `page-break-inside: avoid`, tablas styled, secciones con page breaks | 1.5.2, 1.5.4 |

**Archivos modificados:**

| Archivo | Cambio | Tarea |
|---------|--------|-------|
| `backend/src/reporting/builder.py` | Expandido: `render_html()`, `generate_pdf()` (weasyprint primary con CSS externo), `markdown_to_pdf()` (pandoc --pdf-engine=xelatex fallback), `_weasyprint_to_pdf()` (markdown→HTML→weasyprint pipeline con CSS inline) | 1.5.4 |
| `backend/src/jobs/workers.py` | `build_report` ahora genera MD siempre + PDF si `format="pdf"` (llama `generate_pdf()`), almacena ambos como artifacts | 1.5.4 |
| `backend/pyproject.toml` | Agregados `weasyprint>=62.0,<64.0` y `markdown>=3.6,<4.0` | 1.5.4 |
| `backend/Dockerfile` | Agregadas system libs para weasyprint: `libpango-1.0-0`, `libpangocairo-1.0-0`, `libgdk-pixbuf2.0-0`, `libffi-dev`, `libcairo2`, `libglib2.0-0` | 1.5.4 |

**Decisiones de diseño:**
- weasyprint como primary porque no requiere LaTeX (~2GB), funciona bien en containers slim
- pandoc + xelatex como fallback si está disponible (mejor tipografía)
- Si ninguno disponible, se guarda HTML como último recurso
- El worker siempre genera Markdown, opcionalmente PDF — ambos se almacenan como artifacts separados

### Ping 6 — Actualización de ToDo.md + cleanup

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `ToDo.md` | Marcados como ✅ todos los items de Fase 1.1–1.5 con descripciones actualizadas |
| `backend/src/agent/orchestrator.py` | Eliminados imports no usados (`datetime`, `AsyncSession`) |
| `backend/src/agent/executor.py` | Refactored `_export_report`: reemplazados `__import__()` calls por imports explícitos |

---

## Sesión 4 — QA Gate H1: T1.3 Agent Loop + Fixes (24 Feb 2026)

**Objetivo**: Completar T1.3 (agent reasoning loop) y corregir bugs restantes.

### Bugs corregidos

| # | Bug | Fix | Archivo(s) |
|---|-----|-----|-----------|
| 9 | Z.ai base URL incorrecto (`open.bigmodel.cn` → `api.z.ai`) — causaba 429 en todas las llamadas | Añadido `ZAI_BASE_URL` configurable; cambiado a `https://api.z.ai/api/coding/paas/v4` | `.env`, `config.py`, `client.py` |
| 10 | Modelo Z.ai obsoleto (`glm-4.5` → `glm-5`) | Actualizado default y `.env` | `.env`, `config.py` |
| 11 | asyncpg "Future attached to a different loop" en Celery fork-pool workers — persistencia fallaba al reusar conexiones entre event loops | `_persist_result()` crea engine dedicado por invocación en vez de reusar el module-level engine | `workers.py` |
| 12 | Timeout de `ZaiClient` insuficiente (120s → 300s) para respuestas largas del LLM | Aumentado `timeout` default a 300s | `client.py` |

### T1.3 Agent Loop — Resultado

- **Session**: `e2db2c28-6ad8-4b0d-b1fe-701b0d154759`
- **Task**: `ec456487-3d9d-4bff-bacd-78505d43ce26`
- **Status**: SUCCESS (10 iterations, 34 messages)
- **Tools ejecutados autónomamente**:
  1. `get_session_state` — verificar estado inicial
  2. `nmap -sV -sC -p- -T4 --open scanme.nmap.org` — full port scan (118s)
  3. `httpx` — HTTP probing (parallel)
  4. `whatweb` — tech detection (parallel)
  5. `summarize_findings` — consolidar resultados
  6. `correlate_findings` — correlación inter-tool
  7. `build_report` — generar Markdown
  8. `nmap -p 9929,31337 --script=banner,vuln` — targeted vuln scan
  9. `httpx` ×2 — probar puertos altos
  10. `build_report` — reporte final
- **Persistence**: nmap, httpx, whatweb resultados persistidos correctamente (targets + artifacts)
- **Veredicto**: ✅ PASS — agent ejecutó ≥3 tools autónomamente, produjo summary y reporte

### QA Gate H1 — Resultado final

| Test | Resultado |
|------|-----------|
| T1.1 Docker build + up | ✅ 5/5 healthy |
| T1.2 Session + recon | ✅ nmap+httpx persisted |
| T1.3 Agent loop | ✅ 10 iters, 8+ tools |
| T1.4 Report MD+PDF | ✅ 3.2KB MD + 29KB PDF |
| T1.5 Scope validator | ✅ OOS→403, blocked→403 |
| T1.6 Concurrency | ✅ 10/10 jobs, 0 failures |

**QA Gate H1: 6/6 PASSED** — Horizonte 1 completo. Ready for Horizon 2.

---

## Sesión 6 — Site Mirror + Secret Scanner (24 Feb 2026)

**Objetivo**: Integrar descarga recursiva de sitios web + análisis estático para detección de secretos hardcodeados, API keys y vulnerabilidades en código fuente.

### Archivos creados

| Archivo | Líneas | Descripción |
|---------|--------|-------------|
| `mcp-cli-security/site_mirror.py` | ~270 | Descarga recursiva en 2 fases: wget + extracción de URLs de JS/HTML/CSS |
| `mcp-cli-security/secret_scanner.py` | ~320 | Motor de escaneo con 20+ reglas regex: API keys, AWS/GCP/Azure creds, JWTs, private keys, DB strings, IPs internas, debug mode, source maps, Slack/GitHub/Stripe tokens |
| `backend/src/parsers/site_mirror.py` | ~60 | Parser `SiteMirrorResult`: fases, archivos, tamaños, tipos |
| `backend/src/parsers/secret_scanner.py` | ~80 | Parser `SecretScanResult` con `to_finding_dict()` para persistencia automática |

### Archivos modificados

| Archivo | Cambio |
|---------|--------|
| `mcp-cli-security/server.py` | +`run_mirror()`, +`run_secret_scan()` con `run_in_executor` |
| `mcp-cli-security/app.py` | +rutas JSON-RPC `mirror_site` y `scan_secrets` |
| `mcp-cli-security/Dockerfile` | +COPY `site_mirror.py`, `secret_scanner.py` |
| `backend/src/parsers/dispatch.py` | +registros `site_mirror` y `secret_scanner` en `_PARSER_MAP` |
| `backend/src/db/persistence.py` | +`_persist_secret_scan()`: itera findings → `dal.create_finding()` |
| `backend/src/agent/tools.py` | +definiciones `mirror_site` y `scan_secrets` en `ALL_TOOLS` (11 total) |
| `backend/src/agent/executor.py` | +dispatchers `_mirror_site` y `_scan_secrets` |
| `backend/src/jobs/workers.py` | +tareas Celery `jobs.run_mirror` y `jobs.run_secret_scan` (5 total) |
| `backend/src/api/tools.py` | +endpoints `POST /tools/mirror` y `POST /tools/scan-secrets` |

### Reglas de detección (secret_scanner)

| ID | Nombre | Severidad |
|----|--------|-----------|
| SEC-001 | Generic API Key | high |
| SEC-002 | Generic Secret | high |
| SEC-003 | Bearer Token | high |
| SEC-005 | Password in Code | critical |
| SEC-010 | AWS Access Key (AKIA*) | critical |
| SEC-011 | AWS Secret Key | critical |
| SEC-012 | Google API Key | high |
| SEC-013 | Azure Storage Key | critical |
| SEC-015 | Firebase Config | medium |
| SEC-020 | JWT Token | medium |
| SEC-030 | Private Key (PEM/PKCS8) | critical |
| SEC-040 | DB Connection String | critical |
| SEC-050 | Internal IP (10.x/172.x/192.168.x) | high |
| SEC-051 | Internal URL Reference | medium |
| SEC-060 | Debug Mode Enabled | medium |
| SEC-065 | Admin Endpoint | medium |
| SEC-070 | Security-Relevant Comment | low |
| SEC-080 | Slack Webhook | high |
| SEC-081 | GitHub Token | critical |
| SEC-082 | Stripe Secret Key | critical |
| SEC-083 | SendGrid API Key | high |
| SEC-084 | Twilio Auth Token | high |
| SEC-086 | Source Map Reference | low |

### Testing

| Test | Resultado |
|------|-----------|
| `POST /tools/mirror` → scanme.nmap.org | ✅ 10 archivos, 49KB, 8.6s, 2 artifacts |
| `POST /tools/scan-secrets` → sin secretos | ✅ 0 findings en sitio limpio |
| `POST /tools/scan-secrets` → con secretos plantados | ✅ 7/7 detecciones: API key, AWS key, DB string, Slack webhook, JWT, debug mode, internal IP |
| Persistencia DB | ✅ 7 findings en tabla `findings` con severity correcta |

---

## Resumen de métricas

| Métrica | Valor |
|---------|-------|
| Archivos Python creados | ~19 (sin contar `__init__.py`) |
| Archivos Python modificados | ~15 |
| Archivos config/template creados | 1 (report.html.j2) |
| Archivos config modificados | 4 (pyproject.toml, Dockerfile×2, ToDo.md) |
| Líneas de código nuevas (aprox.) | ~4,300 |
| Endpoints API nuevos | 13 |
| Celery tasks | 5 (run_tool, run_agent, build_report, run_mirror, run_secret_scan) |
| Parsers implementados | 7 + dispatcher |
| Secret detection rules | 23 |
| Tareas ToDo completadas | 28 de 28 (H1) + QA Gate 6/6 + Site Mirror feature |
| Pendiente H1 | Ninguno — **Horizonte 1 COMPLETO + Site Mirror** |
