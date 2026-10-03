# apps/backend/Dockerfile
#
# Build context MUST be the repository root — see docker-compose.yml's
# `build: {context: ., dockerfile: apps/backend/Dockerfile}`.

FROM python:3.11-slim

WORKDIR /app

COPY apps/backend/requirements.txt apps/backend/requirements.txt
COPY analysis analysis
RUN pip install --no-cache-dir -r apps/backend/requirements.txt

COPY packages packages
COPY apps apps
COPY data data
COPY sandbox sandbox

ENV PYTHONPATH=/app:/app/apps:/app/packages:/app/analysis:/app/analysis/static
EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
