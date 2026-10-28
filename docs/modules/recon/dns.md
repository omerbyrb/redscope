# DNS Recon

**Module:** `dns` | **Category:** Recon

Enumerates DNS records, attempts zone transfers, checks for dangling CNAMEs, and audits SPF/DMARC configuration.

## Usage

```bash
redscope scan example.com --modules dns
```

## What It Checks

| Check | Severity | Description |
|-------|----------|-------------|
| A / AAAA records | info | IPv4 and IPv6 resolution |
| MX records | info | Mail server enumeration |
| NS records | info | Nameserver enumeration |
| TXT records | info | All TXT records (SPF, DMARC, verification tokens) |
| CNAME records | info | Canonical name chain |
| SOA record | info | Start of authority |
| Zone transfer (AXFR) | critical | Attempt AXFR against each nameserver |
| Dangling CNAME | high | CNAMEs pointing to unclaimed resources |
| SPF `+all` | high | Overly permissive SPF policy |
| No SPF / No DMARC | high | Missing email authentication records |

## Example Output

```
[DNS] example.com
  A        → 93.184.216.34
  MX       → mail.example.com (priority 10)
  NS       → ns1.example.com, ns2.example.com
  TXT      → v=spf1 include:_spf.google.com ~all
  SOA      → ns1.example.com admin.example.com 2024010101

  [FINDING] Missing DMARC Record — high
    example.com has no DMARC policy. Email spoofing is trivially possible.
    Remediation: Add _dmarc.example.com TXT record: v=DMARC1; p=quarantine; rua=mailto:...
```

## Findings

- **Zone Transfer Successful** — critical — Full zone data was retrieved
- **Dangling CNAME Detected** — high — CNAME points to unclaimed resource
- **SPF Too Permissive** — high — `+all` allows any host to send as the domain
- **Missing SPF Record** — high — No SPF TXT record found
- **Missing DMARC Record** — high — No `_dmarc` TXT record found
- **DMARC Policy None** — medium — `p=none` means emails are not rejected
