FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Repos cloned/mounted under /repos
VOLUME /repos

RUN addgroup --system appuser && adduser --system --ingroup appuser appuser && \
    chown -R appuser:appuser /app /repos
USER appuser

EXPOSE 9400

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9400"]
