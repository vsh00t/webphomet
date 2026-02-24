# MCP CLI-Security Server

Docker image bundling common security / pentesting CLI tools, designed to be
called by the WebPhomet MCP Gateway over JSON-RPC.

## Included Tools

| Tool         | Purpose                          | Source       |
|--------------|----------------------------------|--------------|
| **nmap**     | Port scanning & service detection| apt          |
| **whatweb**  | Web technology fingerprinting    | apt          |
| **subfinder**| Subdomain discovery              | Go (PD)      |
| **httpx**    | HTTP probing & tech detection    | Go (PD)      |
| **nuclei**   | Template-based vuln scanning     | Go (PD)      |
| **ffuf**     | Web fuzzing (dirs, params, …)    | Go           |
| **dalfox**   | XSS scanner & parameter analysis | Go           |
| **kxss**     | Reflected parameter finder       | Go           |
| **sqlmap**   | SQL injection detection          | pip          |
| **schemathesis** | API schema fuzzing           | pip          |

## Build

```bash
docker build -t webphomet/mcp-cli-security .
```

## Usage

This image is consumed as a service in the main `docker-compose.yml`.
The MCP server listens for JSON-RPC requests and executes tools within
strict scope boundaries enforced by the WebPhomet backend.

## Security Notes

- **Scope enforcement** – every command invocation is validated against the
  session's scope before execution.
- **Allowed commands whitelist** – only the tools listed above can be run.
- **Non-root** – in production the container should run as a non-root user
  (see hardening TODO).
