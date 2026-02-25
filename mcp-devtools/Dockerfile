FROM python:3.12-slim

WORKDIR /app

# System deps for Playwright — use official deps installer
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers + system deps (Chromium only)
RUN playwright install --with-deps chromium

COPY . .

EXPOSE 9300

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9300"]
