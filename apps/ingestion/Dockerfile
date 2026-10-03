# apps/ingestion/Dockerfile
#
# Build context is the repository root (see docker-compose.yml) so that
# `from ingestion.india_scam_triage import ...` resolves cleanly.

FROM python:3.11-slim

WORKDIR /app

COPY apps/ingestion/requirements.txt apps/ingestion/requirements.txt
RUN pip install --no-cache-dir -r apps/ingestion/requirements.txt

COPY apps/ingestion apps/ingestion

ENV PYTHONPATH=/app/apps
EXPOSE 8001

CMD ["uvicorn", "ingestion.gateway:app", "--host", "0.0.0.0", "--port", "8001"]
