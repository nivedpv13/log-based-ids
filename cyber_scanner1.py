import re
import os
import sys
import urllib.parse
import urllib.request
import json
from datetime import datetime

# --- CONFIGURATION ---
THRESHOLD = 3 
REPORT_FILE = "security_report.txt"

# --- SIGNATURES ---
SIGNATURES = {
    "SQL Injection": r"('|\"|%27|%22|union\s+select|select\s+.*\s+from|drop\s+table|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    "File Deletion": r"(rm\s+-rf|unlink|delete\s+file|deleted\s+object)",
    "Path Traversal": r"(\.\./\.\./|/etc/passwd|/boot.ini)"
}

def get_ip_location(ip):
    """Fetches the physical location of a public IP address."""
    # Skip private/internal IP ranges
    if ip.startswith(("192.", "10.", "172.", "127.")):
        return "Internal Network"
    
    try:
        # Using ip-api.com (Free for non-commercial use)
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return f"{data.get('city')}, {data.get('country')}"
    except:
        return "Location Lookup Failed"
    return "Unknown Location"

def analyze_logs(log_path):
    failed_logins = {} 
    alerts = []
    
    if not os.path.exists(log_path):
        print(f"Error: File {log_path} not found.")
        return

    print(f"[*] Starting Analysis on: {log_path}")

    with open(log_path, "r") as file:
        for line in file:
            clean_line = urllib.parse.unquote(line).lower()
            
            # Extract IP Address using Regex
            ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
            ip = ip_match.group() if ip_match else "Unknown IP"
            
            # 1. Brute Force Logic
            if "failed" in clean_line or "401" in clean_line:
                failed_logins[ip] = failed_logins.get(ip, 0) + 1
            
            # 2. Pattern Attack Logic
            for attack_type, pattern in SIGNATURES.items():
                if re.search(pattern, clean_line):
                    location = get_ip_location(ip)
                    alerts.append(f"[ALERT] {attack_type} | Source: {ip} ({location}) | Data: {line.strip()}")

    # 3. Check Brute Force Threshold
    for ip, count in failed_logins.items():
        if count >= THRESHOLD:
            location = get_ip_location(ip)
            alerts.append(f"[ALERT] Brute Force | Source: {ip} ({location}) | Attempts: {count}")

    write_report(log_path, alerts)

def write_report(source, alerts):
    with open(REPORT_FILE, "w") as f:
        f.write("="*50 + "\n")
        f.write(f"           CYBER SECURITY SCAN REPORT\n")
        f.write("="*50 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analyzed File: {source}\n")
        f.write("-" * 50 + "\n\n")
        
        if not alerts:
            f.write("No threats detected. System appears secure.\n")
        else:
            for alert in alerts:
                f.write(alert + "\n")
                
    print(f"[+] Scan complete! View your results in: {REPORT_FILE}")

if __name__ == "__main__":
    print("--- Log-Based Intrusion Detection System (IDS) v1.0 ---")
    if len(sys.argv) < 2:
        print("Usage: python cyber_scanner_v2.py <path_to_log_file>")
    else:
        analyze_logs(sys.argv[1])