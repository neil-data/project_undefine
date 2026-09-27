# backend/Dockerfile
#
# Build context MUST be the repository root — see docker-compose.yml's
# `build: {context: ., dockerfile: backend/Dockerfile}`. The backend imports
# sibling packages that live outside backend/ (agents/, static_analysis/),
# matching how this project is already run today per backend/app/main.py's
# own docstring ("uvicorn backend.app.main:app" run from the repo root) —
# this Dockerfile just containerizes that same layout instead of inventing
# a different one.

FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
COPY static-analysis static-analysis
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY agents agents
COPY backend backend
COPY storage storage
COPY dynamic-sandbox dynamic-sandbox
COPY ingestion ingestion

ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
