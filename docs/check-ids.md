# Check IDs

Every finding can carry a `check_id`: a stable identifier of the form `<module>.<check>`.
Titles are written for humans and may be reworded between releases; check IDs are not. Tools
that consume RedScope findings (for example a compliance mapper) should match on `check_id`,
never on titles.

A check ID is **stable**: once released it keeps its meaning. A check that changes meaning
gets a new ID, and removing an ID is a breaking change noted in the changelog.

The modules below emit a check ID on every finding. Other modules will be migrated over time;
their findings have `check_id: null` until then. A test keeps this table in sync with the code.

## Recon

| Check ID | Meaning |
|---|---|
| `portscan.open_ports_summary` | Summary of all open TCP ports found (informational) |
| `portscan.risky_service_exposed` | A port associated with a risky service (e.g. Telnet, RDP, databases) is reachable from the internet |

## Network

| Check ID | Meaning |
|---|---|
| `banner.eol_software` | A service banner shows end-of-life or outdated software |
| `banner.services_fingerprinted` | Summary of services identified from banners (informational) |
| `banner.version_disclosed` | HTTP headers disclose software versions |
| `cvelookup.known_vulnerability` | A detected software version has a known CVE |
| `serviceenum.ftp_anonymous_login` | FTP allows anonymous login |
| `serviceenum.ssh_weak_algorithms` | SSH server advertises weak key exchange, cipher or MAC algorithms |
| `serviceenum.smtp_open_relay` | SMTP server relays mail for arbitrary senders |
| `serviceenum.smtp_vrfy_enabled` | SMTP `VRFY` allows user enumeration |
| `serviceenum.smtp_expn_enabled` | SMTP `EXPN` discloses mailing list members |
| `serviceenum.dns_open_recursion` | DNS server answers recursive queries for anyone |
| `serviceenum.dns_version_disclosed` | DNS server discloses its version |
| `serviceenum.redis_no_auth` | Redis is reachable without authentication |
| `serviceenum.elasticsearch_no_auth` | Elasticsearch is reachable without authentication |
| `serviceenum.mongodb_no_auth` | MongoDB is reachable without authentication |
| `serviceenum.memcached_no_auth` | Memcached is reachable without authentication |
| `serviceenum.zookeeper_no_auth` | ZooKeeper is reachable without authentication |
| `serviceenum.mail_starttls_missing` | POP3/IMAP server does not advertise STARTTLS |
| `serviceenum.smb_signing_not_required` | SMB server does not require message signing |
| `ssltls.cert_expired` | TLS certificate has expired |
| `ssltls.cert_expiring_soon` | TLS certificate expires within 30 days (severity rises as expiry nears) |
| `ssltls.cert_validity_too_long` | TLS certificate validity exceeds 398 days |
| `ssltls.cert_hostname_mismatch` | TLS certificate does not match the hostname |
| `ssltls.deprecated_protocol` | Server accepts a deprecated protocol (SSLv2, SSLv3, TLS 1.0, TLS 1.1) |
| `ssltls.weak_cipher` | Negotiated cipher suite is weak |
| `ssltls.weak_key_length` | Negotiated cipher uses an insufficient key length |
| `ssltls.hsts_missing` | HTTPS response has no `Strict-Transport-Security` header |
| `ssltls.hsts_max_age_too_short` | HSTS `max-age` is shorter than recommended |

## Web

| Check ID | Meaning |
|---|---|
| `headers.missing_security_header` | A recommended HTTP security header is missing |
| `headers.info_disclosure` | A response header discloses implementation details |
| `headers.http_not_redirected` | Plain HTTP is served without redirecting to HTTPS |
