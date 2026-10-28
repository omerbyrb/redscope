# Web Dashboard

RedScope includes a Flask-based web dashboard for running and monitoring scans through a browser interface.

## Starting the Dashboard

=== "Local"

    ```bash
    redscope dashboard
    ```

    Opens on `http://localhost:5000`

=== "Docker"

    ```bash
    docker run --rm -p 5000:5000 -v $(pwd)/output:/app/output \
      redscope dashboard --host 0.0.0.0
    ```

=== "Custom Port"

    ```bash
    redscope dashboard --port 8080
    ```

## Dashboard Features

- **Module Picker** — select which modules to run via chips/buttons
- **Real-time Output** — findings stream in as the scan progresses
- **Scan History** — sidebar showing all previous scans
- **Report Download** — download HTML/JSON reports directly from the UI
- **Dark Theme** — designed for security professionals

## API Endpoints

The dashboard exposes a REST API for programmatic access:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scan/<id>` | Poll scan status and results |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scan/<id>/report` | Download HTML report |

### Start a Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "modules": ["headers", "sqli", "xss", "cors"]
  }'
```

Response:
```json
{
  "scan_id": "abc123",
  "status": "running",
  "target": "https://example.com"
}
```

### Poll for Results

```bash
curl http://localhost:5000/api/scan/abc123
```

Response:
```json
{
  "scan_id": "abc123",
  "status": "complete",
  "findings": [...],
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3
  }
}
```

## Notes

- Scans run in background threads — you can start multiple scans simultaneously
- Results are stored in the `output/` directory
- The dashboard has no authentication — **do not expose it to the internet**
