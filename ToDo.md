# WebPhomet — Plan de Desarrollo

> **Sistema autónomo de pentesting** orquestado por IA (Z.ai GLM-4.5/4.6), Caido, Chrome DevTools MCP y herramientas de seguridad externas.
>
> Fecha de inicio: Febrero 2026  
> Filosofía de despliegue: **todo en contenedores Docker** salvo Chrome host (rendimiento GPU/display) y Caido Desktop.
>
> **Última actualización**: 24 Feb 2026 — **QA Gate H1: 6/6 tests PASSED** ✅. Bugs encontrados y corregidos: libgdk-pixbuf package rename, pythonjsonlogger import, MCP error: null handling, httpx AsyncClient event loop, scope validation wiring, Z.ai base URL (open.bigmodel.cn → api.z.ai), asyncpg event loop reuse in Celery fork workers.

---

## Convenciones

- ✅ Completado
- 🔄 En progreso
- ⬜ Pendiente
- 🧪 Fase de pruebas / QA gate
- 🐳 Requiere contenedor
- 🖥️ Instalación nativa (justificación incluida)

---

## Horizonte 1 — Fundamentos (Semanas 1–8)

> **Objetivo**: Backend orquestador funcional, MCP CLI-Security containerizado, integración básica con Z.ai, recon automatizado y reporting mínimo.

### Fase 1.1 — Infraestructura base (Semanas 1–2)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 1.1.1 | Definir monorepo: estructura de carpetas, linter, formatter, CI básico (GitHub Actions) | Setup | 🔄 (estructura OK, CI pendiente) |
| 1.1.2 | `docker-compose.yml` maestro con servicios: `postgres`, `redis`, `backend`, `celery-worker`, `mcp-cli-security` + healthchecks | 🐳 | ✅ |
| 1.1.3 | Imagen Docker **mcp-cli-security**: incluir `nmap`, `subfinder`, `httpx`, `whatweb`, `nuclei`, `ffuf`, `dalfox`, `kxss`, `schemathesis`, `sqlmap` + FastAPI JSON-RPC server | 🐳 | ✅ |
| 1.1.4 | Imagen Docker **backend**: Python 3.12 (FastAPI), deps, health check | 🐳 | ✅ |
| 1.1.5 | PostgreSQL: esquema inicial — tablas `sessions`, `targets`, `findings`, `artifacts`, `tool_runs` | 🐳 | ✅ |
| 1.1.6 | Redis: configuración de colas (Celery) para job runner | 🐳 | ✅ |
| 1.1.7 | `.env.example` + gestión de secretos (Caido API key, Z.ai API key, DB creds, MCP URL) | Setup | ✅ |
| 1.1.8 | Documentación `README.md`: requisitos, quickstart con `docker compose up` | Docs | ✅ |

### Fase 1.2 — Backend Orquestador core (Semanas 3–4)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 1.2.1 | API REST: endpoints `POST /sessions`, `GET /sessions/:id`, `DELETE /sessions/:id` | Backend | ✅ |
| 1.2.2 | Módulo **Job Runner**: submit job → Redis/Celery → worker ejecuta vía MCP JSON-RPC y reporta resultado | Backend | ✅ |
| 1.2.3 | Módulo **Storage**: DAL (Data Access Layer) sobre PostgreSQL + almacenamiento de artefactos en volumen Docker | Backend | ✅ |
| 1.2.4 | MCP Gateway: cliente JSON-RPC 2.0 async (httpx) con routing a MCP servers por nombre | Backend | ✅ |
| 1.2.5 | Logging centralizado: structured logs (JSON) con `session_id`, `actor`, `tool`, `params`, `result` | Backend | ✅ |
| 1.2.6 | Healthcheck: `/health` en backend y mcp-cli-security, Docker healthchecks configurados | Backend | ✅ |

### Fase 1.3 — MCP CLI-Security (Semanas 4–5)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 1.3.1 | MCP server `cli-security`: FastAPI + JSON-RPC con `run_command`, `tools/list`, healthcheck | MCP 🐳 | ✅ |
| 1.3.2 | Whitelist (`ALLOWED_COMMANDS`) + `ScopeValidator` (hosts/IPs/CIDR, target extraction, blocked IPs) | Seguridad | ✅ |
| 1.3.3 | Parsers de output: `parse_nmap_xml`, `parse_subfinder_json`, `parse_httpx_json`, `parse_whatweb_json`, `parse_nuclei_json` + dispatcher | Parsers | ✅ |
| 1.3.4 | Almacenamiento automático de outputs en DB (`tool_runs` + `artifacts`) via `persistence.py` | Backend | ✅ |
| 1.3.5 | Timeout configurable por ejecución (600s default) + concurrencia Celery (4 workers) | Seguridad | ✅ |

### Fase 1.4 — Integración Z.ai Agent Layer (Semanas 5–6)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 1.4.1 | Cliente Z.ai API: wrapper para GLM-4.5/4.6 con soporte de tools y thinking mode | Agent | ✅ |
| 1.4.2 | Definición de tools Z.ai — Gestión de sesión: `create_pentest_session`, `get_session_state` | Agent | ✅ |
| 1.4.3 | Definición de tools Z.ai — Recon: `run_recon`, `get_recon_results` | Agent | ✅ |
| 1.4.4 | Definición de tools Z.ai — Análisis: `parse_nmap_output`, `summarize_findings`, `correlate_findings` | Agent | ✅ |
| 1.4.5 | Loop de razonamiento: plan → execute tool → evaluate → re-plan (máx 30 iteraciones) + executor dispatch + async polling | Agent | ✅ |
| 1.4.6 | Política de safe_mode: blacklist tools destructivos (sqlmap/dalfox/kxss), args peligrosos, rate limits (60/hr/session) | Seguridad | ✅ |

### Fase 1.5 — Reporting mínimo (Semanas 7–8)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 1.5.1 | Módulo Reporting: modelo de datos de reporte (secciones, findings, PoCs) + `ReportBuilder` | Backend | ✅ |
| 1.5.2 | Plantillas Markdown + HTML: portada, resumen ejecutivo, alcance, hallazgos técnicos, anexos, severity badges | Templates | ✅ |
| 1.5.3 | Tools Z.ai: `build_report(session_id)`, `export_report(session_id, format)` | Agent | ✅ |
| 1.5.4 | Generación de PDF: `weasyprint` (primary) + `pandoc` (fallback), CSS styled | 🐳 | ✅ |

### 🧪 QA Gate H1 — Pruebas de integración del núcleo (Fin Semana 8)

| # | Prueba | Criterio de aceptación | Estado |
|---|--------|----------------------|--------|
| T1.1 | `docker compose up` levanta todos los servicios sin errores | Todos los healthchecks pasan en < 60s | ✅ 5/5 healthy |
| T1.2 | Crear sesión y ejecutar recon completo contra target de prueba (scanme.nmap.org) | Session creada, nmap+httpx ejecutados, resultados en DB | ✅ nmap+httpx OK, targets+artifacts persisted |
| T1.3 | Z.ai genera plan de recon y lo ejecuta autónomamente | Loop agent ejecuta ≥3 tools y produce summary | ✅ 10 iters, 8+ tools (nmap×2, httpx×3, whatweb, summarize, correlate, build_report×2), 34 msgs |
| T1.4 | Generar reporte Markdown y PDF con findings de recon | Reporte contiene secciones obligatorias, PDF legible | ✅ MD 3.2KB + PDF 29KB generados |
| T1.5 | Scope validator rechaza comandos fuera de alcance | Intento de nmap a IP fuera de scope → error bloqueado | ✅ 192.168.1.1 → 403, sqlmap → 403 |
| T1.6 | Test de carga: 10 jobs concurrentes sin deadlocks | Jobs completados, sin errores de concurrencia | ✅ 10/10 success, 0 failures |

---

## Horizonte 2 — Caido + DevTools + Vuln Testing (Semanas 9–18)

> **Objetivo**: Integración completa con Caido y Chrome DevTools, pruebas automáticas de OWASP Top 10 críticas (Injection, XSS, SSRF, Broken Auth), discovery avanzado.

### Fase 2.1 — MCP Caido (Semanas 9–11)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 2.1.1 | Investigar API/WebSocket de Caido + diseñar especificación del MCP Caido | Research | ⬜ |
| 2.1.2 | Implementar MCP server `caido-mcp`: `list_projects`, `select_project`, `get_requests`, `get_issues`, `create_issue` | MCP | ⬜ |
| 2.1.3 | `run_workflow(workflow_id, params)` y `get_workflow_results(run_id)` | MCP | ⬜ |
| 2.1.4 | Sincronización bidireccional Caido issues ↔ DB findings | Backend | ⬜ |
| 2.1.5 | Workflows Caido predefinidos: tagging de params sospechosos, detección de errores SQL, redirecciones | Config | ⬜ |
| 2.1.6 | Tools Z.ai: `caido_list_projects`, `caido_get_requests`, `caido_run_workflow`, `caido_get_issues` | Agent | ⬜ |

> **Nota**: Caido Desktop se ejecuta nativamente 🖥️ (requiere GUI/proxy local). El MCP Caido corre en contenedor y se conecta a la API de Caido host vía red Docker.

### Fase 2.2 — MCP DevTools + Navegación automatizada (Semanas 11–13)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 2.2.1 | Chrome en modo debug: evaluar headless en contenedor vs nativo (rendimiento) | Research | ⬜ |
| 2.2.2 | Integrar Chrome DevTools MCP: `open_page`, `evaluate_js`, `fill_input`, `click`, `wait_for` | MCP | ⬜ |
| 2.2.3 | `get_network_events`, `get_console_logs`, `capture_dom_snapshot` | MCP | ⬜ |
| 2.2.4 | Configurar proxy del navegador → Caido automáticamente + cert CA | Config | ⬜ |
| 2.2.5 | Auth flows: login clásico (user/pass), TOTP (con `totp_generator` en MCP CLI-Security) | MCP | ⬜ |
| 2.2.6 | Tools Z.ai: `devtools_run_flow`, `devtools_get_network_log`, `devtools_get_console_errors` | Agent | ⬜ |
| 2.2.7 | Gestión de múltiples contextos de navegador (sesiones paralelas, roles distintos) | Backend | ⬜ |

> **Decisión de contenedores**: Chrome headless puede correr en contenedor (`browserless/chrome` o similar 🐳). Si se necesita display para debug, usar Chrome nativo 🖥️ con remote debugging.

### Fase 2.3 — Discovery y mapeo avanzado (Semanas 13–14)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 2.3.1 | Crawling automatizado: Z.ai orquesta DevTools para navegar sitio → tráfico capturado en Caido | Agent | ⬜ |
| 2.3.2 | Clasificación de endpoints: auth/no-auth, CRUD, admin, redirect, API | Backend | ⬜ |
| 2.3.3 | Directory/file fuzzing con `ffuf` (contenedor) sobre paths descubiertos | 🐳 | ⬜ |
| 2.3.4 | API schema discovery: detección automática de OpenAPI/GraphQL + `schemathesis` | 🐳 | ⬜ |
| 2.3.5 | Tool Z.ai: `get_attack_surface(session_id)` — resumen consolidado de superficie | Agent | ⬜ |

### Fase 2.4 — Pruebas OWASP: Injection + XSS (Semanas 14–16)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 2.4.1 | Tool `test_injection(endpoint_descriptor)`: orquesta `sqlmap`/`nuclei` vía MCP CLI-Security | Agent 🐳 | ⬜ |
| 2.4.2 | Validación de SQLi: confirmar con time-based/error-based, deduplicar | Backend | ⬜ |
| 2.4.3 | Tool `test_xss(endpoint_descriptor)`: orquesta `dalfox`/`kxss` + validación DevTools | Agent 🐳 | ⬜ |
| 2.4.4 | Validación de XSS: DevTools ejecuta payload y captura console/alert/beacon | Backend | ⬜ |
| 2.4.5 | Generación automática de PoC por finding (request reproducible + pasos) | Backend | ⬜ |
| 2.4.6 | Correlación y deduplicación de findings (misma URL+param+tipo) | Backend | ⬜ |

### Fase 2.5 — Pruebas OWASP: SSRF + Broken Auth (Semanas 16–18)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 2.5.1 | Servidor OOB (out-of-band) callback en contenedor (`interactsh` o custom) | 🐳 | ⬜ |
| 2.5.2 | Tool `test_ssrf(endpoint_descriptor)`: fuzz de params URL/callback + validación OOB | Agent 🐳 | ⬜ |
| 2.5.3 | Tool `test_broken_auth(endpoint_descriptor, accounts)`: enum usuarios, bypass MFA, session fixation | Agent | ⬜ |
| 2.5.4 | AuthZ testing: horizontal + vertical con múltiples contextos DevTools | Agent | ⬜ |
| 2.5.5 | Integración de resultados OWASP en pipeline de reporting | Backend | ⬜ |

### 🧪 QA Gate H2 — Pruebas end-to-end con DVWA/Juice Shop (Fin Semana 18)

| # | Prueba | Criterio de aceptación | Estado |
|---|--------|----------------------|--------|
| T2.1 | Target: DVWA (contenedor). Flujo completo recon → discovery → injection → XSS → report | ≥3 findings reales detectados y reportados con PoC | ⬜ |
| T2.2 | Target: OWASP Juice Shop (contenedor). Auth bypass + SSRF + SQLi | Findings correlacionados y deduplicados correctamente | ⬜ |
| T2.3 | Caido captura todo el tráfico del flujo automatizado | Sitemap completo, issues sincronizados con DB | ⬜ |
| T2.4 | DevTools: login automatizado con user/pass en DVWA | Sesión establecida, cookie capturada, navegación post-auth funcional | ⬜ |
| T2.5 | Multi-rol: 2 cuentas, test de AuthZ horizontal | Finding de IDOR detectado en Juice Shop | ⬜ |
| T2.6 | Reporte PDF completo con todas las secciones | Calidad "entregable a cliente" (revisión manual) | ⬜ |
| T2.7 | Safe mode: payloads destructivos bloqueados | DELETE/PUT a endpoints críticos rechazados con safe_mode=true | ⬜ |

---

## Horizonte 3 — Code-Aware, Móvil, Refinamiento y Producción (Semanas 19–30)

> **Objetivo**: Análisis de código fuente integrado, soporte móvil, breakpoints manuales, panel de control, hardening y documentación final.

### Fase 3.1 — MCP Git/Code + Code-Aware Dynamic Testing (Semanas 19–21)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.1.1 | MCP server `git-code`: `list_repos`, `get_tree`, `get_file`, `search_code` | MCP 🐳 | ⬜ |
| 3.1.2 | Tool `summarize_risks(code_snippet, language, context)` — Z.ai analiza código | Agent | ⬜ |
| 3.1.3 | Pipeline: análisis estático → identificar hotspots → generar lista priorizada de endpoints | Backend | ⬜ |
| 3.1.4 | Feed-back loop: hotspots → Caido workflows focalizados → fuzzing dirigido | Agent | ⬜ |
| 3.1.5 | Correlación code ↔ dynamic findings (vincular finding a línea de código fuente) | Backend | ⬜ |

### Fase 3.2 — Soporte móvil (Semanas 21–23)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.2.1 | Documentación: guía de configuración de emulador Android + proxy Caido | Docs | ⬜ |
| 3.2.2 | Imagen Docker con Android Emulator (si viable) o guía de Genymotion nativo 🖥️ | 🐳/🖥️ | ⬜ |
| 3.2.3 | Instalación automática de cert CA en emulador (script) | Tools | ⬜ |
| 3.2.4 | Análisis de tráfico móvil: Caido captura, Z.ai analiza endpoints descubiertos | Agent | ⬜ |
| 3.2.5 | Tool `analyze_mobile_traffic(session_id)`: resume endpoints API de la app | Agent | ⬜ |

### Fase 3.3 — Breakpoints y modo semi-automático (Semanas 23–24)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.3.1 | Sistema de breakpoints configurables por fase (post-recon, post-OWASP, pre-exploit) | Backend | ⬜ |
| 3.3.2 | WebSocket para notificaciones en tiempo real al operador | Backend | ⬜ |
| 3.3.3 | Modo semi-auto: Z.ai propone acción → espera confirmación humana → ejecuta | Agent | ⬜ |
| 3.3.4 | UI mínima (CLI interactiva o web) para aprobar/rechazar/modificar pasos | Frontend | ⬜ |

### Fase 3.4 — Panel de control y UX (Semanas 24–27)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.4.1 | Frontend web (React/Vue/Svelte) en contenedor: dashboard de sesiones | Frontend 🐳 | ⬜ |
| 3.4.2 | Vista de sesión: progreso por fase, findings en tiempo real, logs | Frontend | ⬜ |
| 3.4.3 | Vista de findings: tabla filtrable, detalle con PoC, export individual | Frontend | ⬜ |
| 3.4.4 | Vista de configuración: targets, scope, credenciales, safe_mode | Frontend | ⬜ |
| 3.4.5 | Gestión de reportes: preview, export, historial de versiones | Frontend | ⬜ |
| 3.4.6 | Autenticación básica del panel (JWT) | Backend | ⬜ |

### Fase 3.5 — Hardening, auditoría y documentación (Semanas 27–29)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.5.1 | Auditoría de seguridad del propio sistema: secrets, permisos contenedores, network policies | Seguridad | ⬜ |
| 3.5.2 | Política de retención de datos configurable (cleanup automático) | Backend | ⬜ |
| 3.5.3 | Tests unitarios: cobertura ≥ 80% en módulos críticos (parsers, validators, MCP handlers) | QA | ⬜ |
| 3.5.4 | Tests de integración automatizados (CI) contra DVWA + Juice Shop | QA | ⬜ |
| 3.5.5 | Documentación completa: arquitectura, API reference, guía de operación, troubleshooting | Docs | ⬜ |
| 3.5.6 | Plantillas de reporte personalizables por cliente | Templates | ⬜ |

### Fase 3.6 — Pruebas reales y refinamiento (Semanas 29–30)

| # | Tarea | Tipo | Estado |
|---|-------|------|--------|
| 3.6.1 | Piloto sobre aplicación real (pre-producción con autorización) | Piloto | ⬜ |
| 3.6.2 | Ajuste de prompts Z.ai según resultados reales (calibración de razonamiento) | Agent | ⬜ |
| 3.6.3 | Ajuste de thresholds de deduplicación y severidad | Backend | ⬜ |
| 3.6.4 | Optimización de tiempos de ejecución (paralelización, caché de resultados) | Perf | ⬜ |

### 🧪 QA Gate H3 — Validación integral (Fin Semana 30)

| # | Prueba | Criterio de aceptación | Estado |
|---|--------|----------------------|--------|
| T3.1 | Flujo "fully autonomous" completo contra HackTheBox web challenge | Findings válidos, reporte profesional generado | ⬜ |
| T3.2 | Flujo con breakpoints: operador interviene en 2 puntos, modifica plan | Sistema respeta breakpoints y aplica cambios | ⬜ |
| T3.3 | Code-aware: repo público con vulns conocidas → hotspots → findings dinámicos | ≥2 findings correlacionados código↔dinámico | ⬜ |
| T3.4 | Tráfico móvil (emulador): app OWASP iGoat/DIVA → endpoints descubiertos → vulns | ≥2 findings de API mobile | ⬜ |
| T3.5 | Panel web: operador crea sesión, monitorea, descarga reporte | UX fluida, sin errores de UI críticos | ⬜ |
| T3.6 | Seguridad: intento de escapar scope, ejecutar comandos no autorizados | Todo bloqueado, log de auditoría completo | ⬜ |
| T3.7 | Carga sostenida: 5 sesiones concurrentes, 50 jobs paralelos | Sin OOM, sin deadlocks, throughput acceptable | ⬜ |

---

## Infraestructura de Contenedores — Resumen

| Componente | Contenedor 🐳 | Nativo 🖥️ | Justificación nativa |
|------------|:-------------:|:---------:|---------------------|
| PostgreSQL | ✅ | | |
| Redis | ✅ | | |
| Backend Orquestador | ✅ | | |
| MCP CLI-Security + todas las tools | ✅ | | Imagen pesada (~2GB) pero aislada |
| MCP Caido | ✅ | | Se conecta a Caido host por red |
| MCP Git/Code | ✅ | | |
| MCP DevTools | ✅ | | |
| Chrome headless | ✅ | (opcional) | Nativo solo si se necesita display/GPU |
| Caido Desktop | | ✅ | Requiere GUI + proxy local en host |
| Servidor OOB (interactsh) | ✅ | | |
| Targets de prueba (DVWA, Juice Shop) | ✅ | | |
| Frontend panel web | ✅ | | |
| PDF generator (pandoc/weasyprint) | ✅ | | |
| Android Emulator (móvil) | (evaluar) | ✅ | Rendimiento KVM/GPU; evaluar viabilidad en Docker |

---

## Stack tecnológico propuesto

| Capa | Tecnología | Notas |
|------|-----------|-------|
| Backend | **Python 3.12** (FastAPI) | Ecosistema rico en seguridad, async, typing |
| Job Queue | **Celery** + Redis | Workers distribuidos, retry, monitoring |
| DB | **PostgreSQL 16** + SQLAlchemy/asyncpg | JSONB para artefactos semiestructurados |
| MCP Servers | **Python** (mcp-sdk) | Protocolo JSON-RPC, fácil de extender |
| Agent Layer | **Python** (z-ai-sdk o HTTP client) | Tools como funciones decoradas |
| Frontend | **React** + TypeScript + Tailwind | (Horizonte 3) |
| Reporting | **Jinja2** templates → Markdown → **Pandoc**/WeasyPrint → PDF | |
| Contenedores | **Docker Compose** (dev) / **Docker Swarm o K8s** (prod futuro) | |

---

## Dependencias externas clave

| Dependencia | Versión mínima | Licencia | Prioridad |
|------------|---------------|----------|-----------|
| Z.ai API (GLM-4.5/4.6) | Latest | Comercial | Horizonte 1 |
| Caido | ≥ 0.40 | Comercial (free tier disponible) | Horizonte 2 |
| Chrome DevTools MCP | Latest | Apache 2.0 | Horizonte 2 |
| nmap | ≥ 7.94 | GPL | Horizonte 1 |
| subfinder | ≥ 2.6 | MIT | Horizonte 1 |
| httpx | ≥ 1.6 | MIT | Horizonte 1 |
| whatweb | ≥ 0.5.5 | GPL | Horizonte 1 |
| nuclei | ≥ 3.2 | MIT | Horizonte 1 |
| sqlmap | ≥ 1.8 | GPL | Horizonte 2 |
| dalfox | ≥ 2.9 | MIT | Horizonte 2 |
| kxss | Latest | MIT | Horizonte 2 |
| ffuf | ≥ 2.1 | MIT | Horizonte 2 |
| schemathesis | ≥ 3.30 | MIT | Horizonte 2 |
| interactsh | ≥ 1.2 | MIT | Horizonte 2 |

---

## Riesgos identificados

| Riesgo | Impacto | Mitigación |
|--------|---------|-----------|
| API de Caido no documentada / limitada | Alto | Investigar API real en H2; implementar fallback con SDK de Caido si existe |
| Z.ai rate limits o latencia alta | Medio | Caché de planes, batching de tool calls, fallback a modelo local |
| Chrome headless inestable en contenedor | Medio | Usar `browserless/chrome` probado; fallback a Chrome nativo |
| Falsos positivos en herramientas | Alto | Doble validación (tool + DevTools confirm); scoring con Z.ai |
| Scope escape accidental | Crítico | Validador multi-capa: MCP + backend + Caido scope rules |
| Complejidad de orquestación multi-MCP | Alto | Empezar con 1 MCP (CLI-Security), agregar incrementalmente |

---

## Métricas de éxito por horizonte

| Horizonte | Métrica | Target |
|-----------|---------|--------|
| H1 | Recon automatizado E2E funcional | ✅ en DVWA |
| H1 | Tiempo de setup (clone → running) | < 5 min con `docker compose up` |
| H2 | Findings reales en Juice Shop | ≥ 5 findings válidos |
| H2 | Tasa de falsos positivos | < 30% |
| H3 | Reporte aceptable por pentester senior (revisión) | Aprobado sin cambios estructurales |
| H3 | Flujo autónomo completo sin intervención | Target simple resuelto en < 2h |
| H3 | Cobertura de tests | ≥ 80% en módulos críticos |
