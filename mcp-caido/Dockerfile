# ──────────────────────────────────────────────────────────────
# MCP Caido — lightweight FastAPI wrapper around Caido's GraphQL API
# ──────────────────────────────────────────────────────────────

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        fastapi \
        uvicorn[standard] \
        httpx \
        pydantic

COPY caido_client.py /app/
COPY server.py /app/
COPY app.py /app/

RUN addgroup --system appuser && adduser --system --ingroup appuser appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 9200

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9200", "--log-level", "info"]
