# Installation

## Requirements

- Python 3.10 or higher
- `nmap` (optional — used by the port scanner module)
- `dnsutils` / `dig` (optional — used for some DNS checks)

## Local Installation

```bash
git clone https://github.com/omerbyrb/redscope
cd redscope
pip install -e .
```

Verify the installation:

```bash
redscope --version
redscope list
```

## Docker Installation

```bash
# Build the image
docker build -t redscope .

# Verify
docker run --rm redscope --version
```

## Optional: Install as a Command

```bash
pip install -e .
redscope --version
```

## Dependencies

RedScope's core dependencies:

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `rich` | Terminal output formatting |
| `requests` | HTTP requests |
| `dnspython` | DNS resolution |
| `flask` | Web dashboard |

Install all at once:

```bash
pip install -r requirements.txt
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'dns'`
```bash
pip install dnspython
```

### Port scanner requires nmap
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Or use Docker which includes nmap pre-installed
docker build -t redscope .
```

### SSL warnings
Some modules use `verify=False` for targets with self-signed certificates. This is expected behavior during security testing. To suppress warnings:
```bash
export PYTHONWARNINGS="ignore:Unverified HTTPS request"
```
