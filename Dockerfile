FROM python:3.11-slim

LABEL maintainer="omerbyrb"
LABEL description="RedScope — Modular Penetration Testing Framework"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Output directory
RUN mkdir -p output

# Entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/redscope-entrypoint
RUN chmod +x /usr/local/bin/redscope-entrypoint

# Default port for dashboard
EXPOSE 5000

ENTRYPOINT ["redscope-entrypoint"]
CMD ["--help"]
