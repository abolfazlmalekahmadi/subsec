# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ML_MODEL_DIR=/app/models/artifacts

WORKDIR /app

# Build deps for confluent-kafka / scientific wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ librdkafka-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN mkdir -p "$ML_MODEL_DIR" \
    && useradd -m -u 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8088/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]
