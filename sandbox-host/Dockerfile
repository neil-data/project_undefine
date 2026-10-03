# E-Rakshak Dynamic Sandbox Host — Production Container
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install runtime tools: strace, tcpdump, qemu-user-static, python3
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    strace \
    tcpdump \
    qemu-user-static \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-privileged runner user
RUN useradd -m -u 1001 -s /bin/bash sandbox-runner

WORKDIR /opt/sandbox

# Install python dependencies in virtual environment
COPY requirements.txt /opt/sandbox/requirements.txt
RUN python3 -m venv /opt/sandbox/venv && \
    /opt/sandbox/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app /opt/sandbox/app
COPY artifacts /opt/sandbox/artifacts

# Ensure permissions
RUN mkdir -p /opt/sandbox/artifacts /opt/sandbox/rootfs && \
    chown -R sandbox-runner:sandbox-runner /opt/sandbox

USER sandbox-runner

ENV PATH="/opt/sandbox/venv/bin:$PATH" \
    SANDBOX_ARTIFACTS_DIR="/opt/sandbox/artifacts" \
    SANDBOX_ROOTFS_DIR="/opt/sandbox/rootfs"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /opt/sandbox/venv/bin/python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
