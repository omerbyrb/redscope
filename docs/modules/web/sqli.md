# SQL Injection

**Module:** `sqli` | **Category:** Web

Detects SQL injection vulnerabilities using error-based and time-based blind techniques across URL parameters and form fields.

## Usage

```bash
python cli.py scan https://example.com/page?id=1 --modules sqli
```

## Techniques

=== "Error-Based"

    Injects payloads that trigger database error messages in the response body.
    Covers 30+ error signatures from MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.

    Example payloads:
    ```
    '
    ''
    ' OR '1'='1
    1' AND SLEEP(0)--
    ```

=== "Time-Based Blind"

    Injects payloads that cause the database to delay response when the condition is true.
    A 4-second threshold is used to confirm blind injection.

    Example payloads:
    ```
    ' OR SLEEP(5)--
    '; WAITFOR DELAY '0:0:5'--
    1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
    ```

## Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| SQL Injection — Error-Based | critical | Database error visible in response |
| SQL Injection — Time-Based Blind | high | Response delayed by injected sleep |

## False Positives

Time-based detection may produce false positives on very slow servers. Increase the timeout threshold in config:

```json
{
  "web": {
    "sqli_time_threshold": 6
  }
}
```

## Limitations

- Does not extract data (detection only)
- Boolean-based blind is not implemented
- Does not test POST body parameters (URL params only)
