# Log-Based Intrusion Detection System (IDS)

A Python command-line tool that analyses log files to detect cyber attacks in real time. 
Built as part of a hands-on cybersecurity portfolio project.

---

## What It Does

This tool reads raw log files and automatically detects three categories of threats:

| Threat | How It's Detected |
|---|---|
| **Brute Force Attacks** | Counts repeated failed login attempts (401 errors) per IP. Triggers alert after 3 failures. |
| **SQL Injection** | Regex pattern matching against known SQLi payloads (UNION SELECT, DROP TABLE, etc.) |
| **Path Traversal** | Detects directory traversal patterns like `../../` and `/etc/passwd` |
| **File Deletion Attacks** | Flags dangerous commands like `rm -rf` in log data |

For every suspicious IP, the tool also performs **live geolocation** using the ip-api.com API — showing the city and country the attack originated from.

---

## Features

- Detects brute force, SQL injection, path traversal, and file deletion attacks
- Real-time IP geolocation for every threat source
- Skips internal/private IPs (192.x, 10.x, 172.x, 127.x) automatically
- Generates a clean, timestamped security report as a `.txt` file
- Works on any standard log file format containing IP addresses

---

## Requirements

No external libraries needed. Uses Python standard library only.

```
Python 3.x
```

---

## How to Run

```bash
python cyber_scanner1.py <path_to_your_log_file>
```

**Example:**
```bash
python cyber_scanner1.py /var/log/auth.log
python cyber_scanner1.py access.log
```

---

## Example Output

```
--- Log-Based Intrusion Detection System (IDS) v1.0 ---
[*] Starting Analysis on: access.log
[+] Scan complete! View your results in: security_report.txt
```

**security_report.txt:**
```
==================================================
           CYBER SECURITY SCAN REPORT
==================================================
Generated: 2026-05-24 10:30:45
Analyzed File: access.log
--------------------------------------------------

[ALERT] Brute Force | Source: 45.33.32.156 (Fremont, United States) | Attempts: 7
[ALERT] SQL Injection | Source: 103.21.244.0 (Mumbai, India) | Data: GET /?id=1' UNION SELECT * FROM users--
[ALERT] Path Traversal | Source: 198.51.100.5 (Amsterdam, Netherlands) | Data: GET /../../etc/passwd
```

---

## How It Works — Technical Overview

```
Log File Input
      |
      v
Line-by-line parsing with urllib.parse.unquote() (handles URL-encoded attacks)
      |
      +---> Regex IP extraction
      |
      +---> Failed login counter per IP (Brute Force detection)
      |
      +---> Signature matching against attack patterns (SQL Injection, Path Traversal, File Deletion)
      |
      v
For each flagged IP --> ip-api.com geolocation API call
      |
      v
security_report.txt generated with timestamped alerts
```

---

## Attack Signatures Detected

```python
"SQL Injection"   : union select, drop table, or '1'='1', %27, %22
"File Deletion"   : rm -rf, unlink, delete file
"Path Traversal"  : ../../, /etc/passwd, /boot.ini
```

---

## Project Context

Built during a 5-month Diploma in Cyber Security (OCSP) at Offenso Hackers Academy, Trivandrum.  
This tool simulates core functionality of a SIEM log parser — detecting, correlating, and reporting threats from raw log data.

---

## Author

**Nived PV**  
Cybersecurity Enthusiast | OCSP | Penetration Testing | SOC  
Kerala, India  
www.linkedin.com/in/nived-pv-
