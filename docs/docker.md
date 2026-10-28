# Docker

RedScope ships with a `Dockerfile` and `docker-compose.yml` for containerized scanning. The Docker image includes `nmap`, `dnsutils`, and `netcat` pre-installed.

## Build the Image

```bash
docker build -t redscope .
```

## Run a Scan

```bash
# Basic scan with output saved to ./output
docker run --rm -v $(pwd)/output:/app/output redscope scan example.com --modules dns

# Full recon with HTML report
docker run --rm -v $(pwd)/output:/app/output \
  redscope scan example.com --all-recon --save --report html

# Web assessment
docker run --rm -v $(pwd)/output:/app/output \
  redscope scan https://example.com --all-web --save --report html
```

## Web Dashboard

```bash
# Start the dashboard on port 5000
docker run --rm -p 5000:5000 -v $(pwd)/output:/app/output \
  redscope dashboard --host 0.0.0.0
```

Open `http://localhost:5000` in your browser.

## Docker Compose

Use `docker-compose.yml` to run the dashboard as a background service:

```bash
# Start dashboard in the background
docker compose --profile dashboard up -d

# View logs
docker compose logs -f dashboard

# Stop
docker compose down
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHODAN_API_KEY` | — | Shodan API key for the shodan module |

```bash
docker run --rm -e SHODAN_API_KEY=your-key \
  -v $(pwd)/output:/app/output \
  redscope scan example.com --modules shodan
```

## Pull from GitHub Container Registry

When a release is tagged, the image is automatically published to GHCR:

```bash
docker pull ghcr.io/omerbyrb/redscope:latest
docker run --rm ghcr.io/omerbyrb/redscope:latest --version
```

## Image Details

- Base: `python:3.11-slim`
- Installed system tools: `nmap`, `iputils-ping`, `dnsutils`, `netcat-openbsd`
- Working directory: `/app`
- Default port: `5000` (dashboard)
- Entrypoint: `docker-entrypoint.sh` → routes to `python -m redscope`
