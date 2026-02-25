# WebPhomet — REST API Reference

> Base URL: `http://localhost:8000/api/v1`  
> Authentication: Optional `X-API-Key` header (set `API_KEY` env var to enable)  
> Content-Type: `application/json`

---

## Sessions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sessions/` | Create a pentest session |
| `GET` | `/sessions/` | List all sessions |
| `GET` | `/sessions/{id}` | Get session details (includes targets, findings, tool runs) |
| `PATCH` | `/sessions/{id}` | Update session (status, config) |
| `DELETE` | `/sessions/{id}` | Delete session and cascade |

### Create Session

```http
POST /api/v1/sessions/
Content-Type: application/json

{
  "target_base_url": "https://example.com",
  "app_type": "web",
  "scope": {
    "allowed_hosts": ["example.com", "*.example.com"],
    "allowed_ips": ["93.184.216.34/32"],
    "blocked_ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  },
  "config": {}
}
```

**Response** `201`:
```json
{
  "id": "uuid",
  "target_base_url": "https://example.com",
  "status": "created",
  "created_at": "2026-02-24T00:00:00Z"
}
```

---

## Findings

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/findings/` | Create a finding |
| `GET` | `/findings/session/{session_id}` | List findings for session |
| `GET` | `/findings/session/{session_id}/summary` | Severity/status statistics |

### Query Parameters (List)

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter by severity (critical, high, medium, low, info) |
| `status` | string | Filter by status (open, confirmed, false_positive, fixed) |

---

## Tools

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/tools/run` | Execute a single tool via Celery |
| `POST` | `/tools/recon` | Launch parallel recon sweep |
| `GET` | `/tools/session/{session_id}` | List tool runs for session |
| `GET` | `/tools/task/{task_id}/status` | Check Celery task status |
| `GET` | `/tools/{tool_run_id}` | Get tool run details |
| `POST` | `/tools/mirror` | Mirror website |
| `POST` | `/tools/secrets` | Scan for secrets |
| `POST` | `/tools/inject` | Run injection tests |
| `POST` | `/tools/auth` | Run auth tests |
| `POST` | `/tools/ssrf` | Run SSRF tests |
| `POST` | `/tools/analyze-mobile-traffic` | Analyse captured mobile traffic |
| `GET` | `/tools/mobile/emulator-status` | Check emulator status |
| `POST` | `/tools/mobile/start-emulator` | Start mobile emulator |

### Run Tool

```http
POST /api/v1/tools/run
Content-Type: application/json

{
  "session_id": "uuid",
  "tool_name": "nmap",
  "args": { "target": "example.com", "flags": "-sV -sC" }
}
```

**Response** `202`:
```json
{
  "status": "submitted",
  "task_id": "celery-task-uuid",
  "tool_run_id": "uuid"
}
```

### Recon Sweep

```http
POST /api/v1/tools/recon
Content-Type: application/json

{
  "session_id": "uuid",
  "target": "example.com",
  "tools": ["subfinder", "nmap", "httpx", "whatweb"]
}
```

---

## Git / Code Analysis

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/git-code/clone-repo` | Clone a Git repository for analysis |
| `GET` | `/git-code/list-repos` | List cloned repositories |
| `POST` | `/git-code/code-audit` | Run full code audit (50+ regex patterns) |
| `POST` | `/git-code/search-code` | Search code for patterns |
| `POST` | `/git-code/find-hotspots` | Find vulnerability hotspots |
| `POST` | `/git-code/git-log` | Git log |
| `POST` | `/git-code/git-diff` | Git diff |
| `POST` | `/git-code/git-blame` | Git blame |
| `POST` | `/git-code/git-tree` | Directory tree |
| `POST` | `/git-code/git-file` | Read file content |

### Clone Repo

```http
POST /api/v1/git-code/clone-repo
Content-Type: application/json

{
  "session_id": "uuid",
  "repo_url": "https://github.com/org/repo.git",
  "branch": "main"
}
```

### Find Hotspots

```http
POST /api/v1/git-code/find-hotspots
Content-Type: application/json

{
  "session_id": "uuid",
  "repo_name": "repo"
}
```

---

## Correlations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/correlations/run` | Run correlation engine |
| `GET` | `/correlations/session/{session_id}` | List stored correlations |
| `GET` | `/correlations/finding/{finding_id}` | Correlations for a specific finding |
| `DELETE` | `/correlations/session/{session_id}` | Clear all correlations for session |

### Run Correlation

The correlation engine links static code hotspots to dynamic findings using 4-factor scoring:
1. **Category match** (weight 0.55) — maps vuln categories (sqli, xss, etc.) to finding types
2. **Path heuristic** (weight 0.15) — URL path similarity to source file paths
3. **Keyword overlap** (weight ≤0.15) — shared tokens between hotspot snippet and finding details
4. **Severity alignment** (weight 0.05) — severity level concordance

```http
POST /api/v1/correlations/run
Content-Type: application/json

{
  "session_id": "uuid",
  "repo_name": "repo",
  "hotspots": [
    {
      "file": "src/controllers/auth.py",
      "line": 42,
      "category": "sqli",
      "snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
      "severity": "high"
    }
  ],
  "min_confidence": 0.3,
  "persist": true
}
```

**Response** `200`:
```json
{
  "correlations": [
    {
      "finding_id": "uuid",
      "finding_title": "SQL Injection in /api/users",
      "hotspot_file": "src/controllers/auth.py",
      "hotspot_line": 42,
      "confidence": 0.85,
      "correlation_type": "category+path"
    }
  ],
  "total": 1
}
```

---

## Agent

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agent/start` | Launch the autonomous pentesting agent |
| `GET` | `/agent/status/{task_id}` | Check agent task status |
| `POST` | `/agent/stop/{task_id}` | Stop agent (Celery revoke) |

### Start Agent

```http
POST /api/v1/agent/start
Content-Type: application/json

{
  "session_id": "uuid",
  "max_iterations": 30,
  "model": "glm-5"
}
```

---

## Breakpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/breakpoints/configure` | Set breakpoint configuration |
| `GET` | `/breakpoints/config/{session_id}` | Get current config |
| `GET` | `/breakpoints/pending` | List pending breakpoints |
| `POST` | `/breakpoints/resolve` | Approve or reject a breakpoint |
| `GET` | `/breakpoints/phases` | List all 8 breakpoint phases |

### 8 Breakpoint Phases

| Phase | Default | When |
|-------|---------|------|
| `pre_recon` | off | Before reconnaissance |
| `post_recon` | **on** | After recon (review discovered targets) |
| `pre_scanning` | off | Before vulnerability scanning |
| `post_scanning` | off | After scanning |
| `pre_exploit` | **on** | Before exploitation attempts |
| `post_exploit` | off | After exploitation |
| `pre_report` | off | Before report generation |
| `post_owasp` | **on** | After OWASP classification |

---

## Admin

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/stats` | Database size statistics |
| `POST` | `/admin/purge` | Purge sessions older than threshold |

---

## WebSocket

| Endpoint | Description |
|----------|-------------|
| `WS /api/v1/ws/{session_id}` | Per-session real-time events (tool progress, findings, breakpoints) |
| `WS /api/v1/ws` | Global broadcast channel |

### Event Types

```json
{ "type": "tool_started", "tool_run_id": "uuid", "tool_name": "nmap" }
{ "type": "tool_completed", "tool_run_id": "uuid", "status": "success" }
{ "type": "finding_created", "finding_id": "uuid", "severity": "high" }
{ "type": "breakpoint_hit", "phase": "pre_exploit", "details": {...} }
```

---

## Health

```http
GET /health
→ { "status": "ok" }
```

---

## Error Responses

All errors follow the standard format:

```json
{
  "detail": "Human-readable error message"
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request / validation error |
| 401 | Invalid or missing API key |
| 403 | Safe mode blocked the operation |
| 404 | Resource not found |
| 413 | Request body too large (>10 MB) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
