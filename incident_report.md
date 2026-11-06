# Incident Reports — DVWA Web Application Attacks

Two incidents were simulated and detected against a deliberately vulnerable web application (DVWA) running in my own lab.

---

## Incident 3: SQL Injection

| Field | Details |
|---|---|
| **Date/Time** | November 4, 2026, 15:51 PM (local) |
| **Source** | 10.0.2.2 (host browser, simulated attacker) |
| **Target** | DVWA SQL Injection lab, `id` parameter |
| **Detected by** | Splunk search / alert: *SQL Injection Attempt - DVWA* |
| **Severity** | High |

### Timeline

1. **Nov 4, 15:51:29** - Payload `1' UNION SELECT user(), database()-- -` submitted to the `id` parameter of the SQL Injection lab via a `GET` request.
2. The application returned `200 OK` and displayed the MySQL username and database name directly on the page — data the form was never designed to expose.
3. **Nov 4-5** - Additional payloads submitted (`1' OR '1'='1`, repeated at several points) while building and debugging the detection search.
4. **Nov 5, 14:55:01 UTC** - The scheduled alert *SQL Injection Attempt - DVWA* fired on its own schedule for the first time, after the detection regex was corrected (see Analysis below).

### Evidence

- `index=main sourcetype=access_combined id=*` — raw event showing the URL-encoded payload in the `id` field: `1%27+UNION+SELECT+user%28%29%2C+database%28%29--+-` (`screenshots/03-sqli-injection-detail.png`).
- Splunk's `access_combined` sourcetype automatically extracted the payload into a queryable `id` field without custom parsing.
- Triggered Alerts entry confirming the alert fired on schedule at 14:55:01 UTC (`screenshots/08-sqli-alert-triggered.png`).

### Analysis

The payload exploits a classic SQL injection pattern: closing the application's intended string literal (`1'`), appending an attacker-controlled `UNION SELECT` query, pulling database metadata via `user()` and `database()`, and using `-- -` to comment out the rest of the original query so it still executes without a syntax error. Because the form returned the results directly on the page, this also demonstrates how SQL injection can lead to direct information disclosure, not just unauthorized data access.

**Detection debugging note:** the first version of the detection regex matched against decoded SQL syntax (a literal `'`, `=`, and whitespace). It missed nearly every real submission, because Splunk's `access_combined` field extraction leaves the `id` value URL-encoded (`%27` rather than `'`). The fix was to match the encoded representation directly (`%27`, `union`, `select`, `--`) rather than assuming the field had been decoded. This is a useful general lesson: always verify what form a field actually takes in the index before writing a regex against it, rather than assuming based on how the original payload was typed.

### Recommended Response

- Use parameterized queries / prepared statements instead of string-concatenated SQL — the root cause of this vulnerability class.
- Apply least-privilege database accounts, so even a successful injection can't read arbitrary data (DVWA intentionally uses an overprivileged account for teaching purposes).
- Deploy a Web Application Firewall (WAF) to catch common injection patterns at the network edge as defense-in-depth.
- Monitor for SQL keywords and comment markers in URL parameters that should only ever contain simple values (as this detection does).

---

## Incident 4: Automated Web Login Brute Force

| Field | Details |
|---|---|
| **Date/Time** | November 5, 2026, 01:47 AM (local) |
| **Source** | 172.17.0.1 (Docker bridge gateway — see note below) |
| **Target** | DVWA Brute Force lab login form (`admin` account) |
| **Detected by** | Splunk search / alert: *Web Login Brute Force - DVWA* |
| **Severity** | High |

### Timeline

1. **Nov 5, 01:47:43** - Hydra (`http-get-form` module) submitted 7 password attempts against the `admin` account within a single second.
2. One attempt, `password=password`, succeeded.
3. Every request, successful or not, returned HTTP status `200` — the form displays its result inline rather than redirecting, so status code alone could not distinguish success from failure.
4. The successful attempt was identified by response size: failed attempts returned a consistent 4666-byte page, while the successful attempt returned a 4704-byte page (a different message block).
5. **Nov 6, 09:55:01 UTC** - The scheduled alert *Web Login Brute Force - DVWA* fired on its own schedule against a repeat Hydra run, confirming the burst-detection logic works end-to-end, not just as a manually-run search.

### Evidence

- `index=main sourcetype=access_combined uri_path="/vulnerabilities/brute/"` — 7 requests within the same second, all with distinct password values visible in plaintext in the URL (`screenshots/04-bruteforce-burst.png`).
- `bytes=4704` isolates the single successful request, confirmed directly via the auto-extracted `username` and `password` fields: `username=admin`, `password=password` (`screenshots/05-bruteforce-success-detail.png`).
- Triggered Alerts entry confirming the alert fired on schedule at 09:55:01 UTC (`screenshots/07-bruteforce-alert-triggered.png`).

### Note on source IP

The source IP recorded is `172.17.0.1`, Docker's bridge gateway address, rather than an external address. This is a known artifact of this specific lab setup: Hydra ran on the same host as the Docker container and connected via `localhost`, so the request passed through Docker's internal bridge network. In a real deployment, the attacker's actual external or internal IP would appear instead.

### Analysis

This incident demonstrates two things beyond the brute force itself. First, credentials transmitted via `GET` requests (as DVWA's Brute Force lab intentionally does) are exposed in plaintext in web server logs, browser history, and any intermediate proxy — a real anti-pattern outside of training labs, where credentials belong in the request body over HTTPS, not the URL. Second, HTTP status code is not a reliable signal for distinguishing login success from failure; response size (or, better, response content) may be the only way to tell them apart when an application handles authentication errors inline.

### Recommended Response

- Rate-limit login attempts per account and per source IP; lock out or CAPTCHA-gate after a threshold of failures.
- Submit credentials via `POST` over HTTPS, never as URL query parameters.
- Alert on a high volume of requests to a login endpoint within a short window, regardless of HTTP status code, since status alone doesn't reveal outcome on every application.
- Enforce password complexity and screen against known weak/breached passwords, so a small wordlist like this one can't succeed in a single pass.

### Debugging note (both incidents)

While verifying that these alerts were actually firing on their own schedule (as opposed to only when run manually), the scheduler's health report briefly implicated itself — Splunk's own **Health Report Manager** flagged a "Search Lag" warning on the Search Scheduler component. Investigating the scheduler's internal log directly (`index=_internal` equivalent, viewed via the health report's "Last 50 related messages") showed every scheduled run completing successfully, every 5 minutes, with `result_count=0`. This ruled out the scheduler as the cause and pointed back to the detection logic itself — the URL-encoding issue described in Incident 3's analysis. The general lesson: when a scheduled alert produces no results, check the saved search's actual logic and the data's actual format before assuming an infrastructure-level fault.

---

## MITRE ATT&CK Mapping

| Detection | Technique |
|---|---|
| SQL injection | T1190 Exploit Public-Facing Application |
| Web login brute force | T1110.001 Brute Force: Password Guessing |
| Credential exposure via GET-based form | T1552 Unsecured Credentials |
