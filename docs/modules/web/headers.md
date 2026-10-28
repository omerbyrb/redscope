# HTTP Security Headers

**Module:** `headers` | **Category:** Web

Analyzes HTTP response headers for missing security controls and information leakage.

## Usage

```bash
redscope scan https://example.com --modules headers
```

## Checks

### Missing Security Headers

| Header | Severity | Risk if Missing |
|--------|----------|----------------|
| `Strict-Transport-Security` | high | Protocol downgrade / MITM attacks |
| `Content-Security-Policy` | high | XSS attacks not mitigated by policy |
| `X-Frame-Options` | medium | Clickjacking attacks |
| `X-Content-Type-Options` | medium | MIME sniffing attacks |
| `Referrer-Policy` | low | Sensitive URLs leak in Referer header |
| `Permissions-Policy` | low | Browser features not restricted |

### Information Leakage

Flags headers that expose server technology:

- `Server: Apache/2.4.51 (Debian)` — reveals server version
- `X-Powered-By: PHP/7.4.3` — reveals language/framework version
- `X-AspNet-Version: 4.0.30319` — reveals .NET version
- `X-Generator: WordPress 6.3` — reveals CMS

### HTTPS Enforcement

Checks whether HTTP requests are redirected to HTTPS with a 301/302 status code.

## Example Output

```
[FINDING] Missing Content-Security-Policy — high
  CSP not set — XSS attacks are not mitigated by policy
  Remediation: Define a strict Content-Security-Policy header

[FINDING] Information Disclosure via Server — info
  Server: nginx/1.18.0
  Remediation: Remove or obfuscate the Server response header

[FINDING] HTTP Not Redirected to HTTPS — high
  http://example.com returned 200 instead of 301
```
