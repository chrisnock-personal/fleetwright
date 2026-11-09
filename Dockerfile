FROM python:3.12-slim

LABEL org.opencontainers.image.title="FleetWright" \
      org.opencontainers.image.description="Manages package updates on Ubuntu and Fedora servers, by agent or over SSH"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fleetwright/ fleetwright/
COPY agent/ agent/

RUN useradd --system --uid 10001 fleetwright \
 && install -d -m 700 -o fleetwright -g fleetwright /data/certs
USER fleetwright

# 8443: HTTPS (dashboard and agent gateway). 8080: redirects to HTTPS
# (or plain HTTP with FLEETWRIGHT_TLS=off, behind a TLS proxy).
EXPOSE 8443 8080
# The worker uses the same image: command: ["python", "-m", "fleetwright.worker"]
CMD ["python", "-m", "fleetwright.serve"]
