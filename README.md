# Web Application Attack Detection with Splunk (DVWA)

A follow-up SOC project: deploying a deliberately vulnerable web app, attacking it, and detecting the attacks with Splunk. Different attack surface than the SSH/host-log project (see [../README.md](../README.md)) — this one works at the HTTP layer.

## Objectives

- Deploy DVWA (Damn Vulnerable Web Application) in Docker
- Get its Apache access log flowing into Splunk continuously
- Attack it with SQL injection and an automated login brute force
- Build Splunk detections and alerts for both attack types
- Document both incidents

## Lab Environment

| Component | Details |
|---|---|
| Target app | DVWA (`vulnerables/web-dvwa` Docker image) |
| Host | Ubuntu VM, hostname `attacker` (same VM as the SSH project) |
| Web server | Apache (inside the container) |
| Log file | `/home/attacker/dvwa_logs/access.log` (host-mounted volume) |
| Sourcetype | `access_combined` |
| Index | `main` |
| Attack tools | Manual SQL injection payloads, THC-Hydra (`http-get-form`) |

## 1. Deployment and Ingestion

```bash
docker run -d --name dvwa -p 8080:80 -v ~/dvwa_logs:/var/log/apache2 vulnerables/web-dvwa
```

The `-v` flag mounts Apache's log directory to a folder on the host, so the access log persists outside the container and Splunk can monitor it continuously, rather than it being lost each time the container restarts.

```bash
sudo -u splunk /opt/splunk/bin/splunk add monitor /home/attacker/dvwa_logs/access.log -sourcetype access_combined -index main -hostname attacker
```


**Issues encountered along the way:**
- **Browser couldn't reach the app from the host machine** (`ERR_CONNECTION_TIMED_OUT`). The VM's NAT network IP isn't reachable from outside the VM by default. Fixed by adding a VirtualBox port-forwarding rule (host port 8080 → guest port 8080), then accessing the app via `localhost:8080` from the host instead of the VM's internal IP.
- **`docker: permission denied`** connecting to the Docker socket. Fixed the same way as the earlier `auth.log` permission issue: added the user to the relevant group (`docker`) and started a new session (`newgrp docker`).
- **`Path does not exist`** when adding the Splunk monitor, even with the correct file path and world-readable file permissions. Cause: the home directory (`/home/attacker`) itself wasn't traversable by other users (`drwxr-x---`), which blocked Splunk from resolving the path at all, independent of the target file's own permissions. Fixed with `chmod o+x /home/attacker`.

## 2. Baseline

```spl
index=main sourcetype=access_combined | stats count by method, status
```

Normal traffic before any attack: a handful of `GET 200`s (page loads), a couple of `POST 302`s (login and settings form submissions), and one `408` request timeout (idle connection, not an attack indicator).

## 3. Attack 1: SQL Injection

**DVWA → SQL Injection**, security level set to Low.

Payload used:
```
1' UNION SELECT user(), database()-- -
```

![SQL injection evidence]

Splunk's `access_combined` parser automatically extracted the payload into an `id` field from the URL query string:
```
id = 1%27+UNION+SELECT+user%28%29%2C+database%28%29--+-
```
URL-decoded: `1' UNION SELECT user(), database()-- -`

**How to read the payload:**
| Part | Function |
|---|---|
| `1'` | Breaks out of the application's intended string value |
| `UNION SELECT` | Appends an attacker-controlled query to the original one |
| `user(), database()` | MySQL functions that leak the DB username and database name — data never meant to be exposed through this form |
| `-- -` | SQL comment; discards the rest of the original query so it still executes without a syntax error |

### Detection

```spl
index=main sourcetype=access_combined uri_path="/vulnerabilities/sqli*" id=*
| regex id="(?i)(union|select|%27|--|;--|#)"
| table _time, clientip, id, status
```

Flags SQL keywords, comment markers, and an encoded single quote (`%27`) inside the `id` parameter.

**Bug found while building this:** an earlier version of this regex looked for decoded characters — a literal `'`, `=`, and real whitespace (`union\s+select`, `or\s*1\s*=\s*1`, `'\s*or\s*'`). It missed almost every real attempt, because Splunk's `access_combined` extraction keeps the `id` field **URL-encoded** (`%27` rather than `'`, `+` rather than a space) — it never decodes it. The fix was to match the encoded forms directly rather than assuming decoded syntax. This cost significant troubleshooting time, at one point incorrectly suspecting the Splunk scheduler itself (via Settings → Health Report Manager, which did surface a real but unrelated "Search Lag" warning) before the actual cause — matching against the wrong representation of the data — was found by testing the regex against known-good events with an unrestricted time range.

**Alert:** `SQL Injection Attempt - DVWA` — scheduled every 5 minutes, triggers when results > 0. Confirmed firing on its own schedule:

![SQL injection alert triggered]

## 4. Attack 2: Automated Login Brute Force

**DVWA → Brute Force** lab (chosen over the main login form because it has no CSRF token, making it scriptable).

```bash
hydra -l admin -P ~/dvwa_wordlist.txt localhost -s 8080 http-get-form \
"/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=<session>"
```

Result:
```
[8080][http-get-form] host: localhost   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
```


All 7 password attempts landed within the same second, the same burst signature as the SSH Hydra attack in the earlier project.

**Distinguishing success from failure was not status-code based.** Every request — successful or not — returned HTTP `200`, since this form displays its error inline rather than redirecting. The actual signal was response size:


| Outcome | bytes |
|---|---|
| Failed attempts | 4666 |
| Successful attempt (`password=password`) | 4704 |

A response size that doesn't match the rest of a group is often a sign something different happened server-side, even when the status code gives no indication.

### Detection

```spl
index=main sourcetype=access_combined uri_path="/vulnerabilities/brute/"
| bin _time span=10s
| stats count by _time, clientip
| where count > 5
```

Same burst-window structure as the SSH detection: flags more than 5 requests from one source within a 10-second window.

**Alert:** `Web Login Brute Force - DVWA` — scheduled every 5 minutes, triggers when results > 0. Confirmed firing on its own schedule:

![Brute force alert triggered]

## 5. Dashboard

Added a **DVWA Attack Activity** panel to the existing Linux Auth Monitoring dashboard:

```spl
index=main sourcetype=access_combined (uri_path="/vulnerabilities/sqli*" OR uri_path="/vulnerabilities/brute/") (id=* OR username=*)
| eval attack_type=if(like(uri_path, "%sqli%"), "SQL Injection", "Brute Force")
| table _time, clientip, attack_type, uri_query, status, bytes
| sort -_time
```


*(Screenshot shown is from before the `(id=* OR username=*)` filter was added to exclude asset requests with no attack parameters — update with a current screenshot once captured.)*

## 6. Incident Reports

Full write-ups: **[INCIDENT_REPORT.md]

## 7. MITRE ATT&CK Mapping

| Detection | Technique |
|---|---|
| SQL injection | T1190 Exploit Public-Facing Application |
| Web login brute force | T1110.001 Brute Force: Password Guessing |
| Credential exposure via GET-based form | T1552 Unsecured Credentials |

## Lessons Learned

- A home directory without execute ("traverse") permission for others will block Splunk from reaching a file inside it, even when the file itself is world-readable — the whole path needs to be walkable, not just the final file.
- Docker containers need an explicit volume mount for logs to survive and be host-readable; otherwise logs only exist inside the container's own filesystem.
- VirtualBox NAT networking requires an explicit port-forwarding rule before the host machine can reach a service running inside the guest VM.
- Not every attack shows up as a failed HTTP status. The DVWA brute-force lab returned `200` for every attempt, success and failure alike — response size was the only distinguishing signal.
- A splunk scheduled alert's time range must use a valid relative range (e.g. "Last 5 minutes"); an invalid or stale custom time range will cause it to silently never fire, with no obvious error shown to the user.
- A regex written against the *decoded* form of data will silently fail if Splunk's field extraction actually keeps that data URL-encoded. Always test a detection regex against a known-good raw event with an unrestricted time range before trusting a "0 results" outcome, rather than assuming the scheduler or search infrastructure is at fault.
- CSRF tokens on a login form (as in DVWA's main login) make naive scripted brute-forcing impractical without first handling token extraction per request — the dedicated Brute Force lab exists specifically to demonstrate the attack without that complexity.

## Tools

Docker, DVWA (`vulnerables/web-dvwa`), Splunk Enterprise, THC-Hydra
