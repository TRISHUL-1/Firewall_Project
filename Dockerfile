# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
# iptables   : packet blocking
# libpcap-dev: required by Scapy for raw packet capture
# iproute2   : useful network utilities (ip, ss)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ───────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# WebSocket support for uvicorn
RUN pip install --no-cache-dir "uvicorn[standard]"

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Runtime config ────────────────────────────────────────────────────────────
# Create logs directory so it exists even before the firewall writes anything
RUN mkdir -p logs

# The API listens on 8000 — expose it so docker-compose / -p flags can reach it
EXPOSE 8000

# Default command starts the API server.
# The firewall process is run separately via docker-compose (needs --privileged).
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]