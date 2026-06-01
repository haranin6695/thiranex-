"""
====================================================
  Vulnerability Scanner - Mini Project
  Compatible with: Python 3.13.0
  Description: Scans for open ports, weak configs,
               outdated software, and generates a
               vulnerability report.
====================================================
"""

import socket
import datetime
import ipaddress
import sys
import re
import urllib.request
import urllib.error
import ssl
import http.client
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

RISKY_PORTS = {23, 21, 135, 139, 445, 5900, 6379, 27017}

OUTDATED_SIGNATURES = {
    "Apache/2.2":    ("Apache 2.2", "Apache 2.4+"),
    "Apache/2.0":    ("Apache 2.0", "Apache 2.4+"),
    "nginx/1.14":    ("Nginx 1.14", "Nginx 1.24+"),
    "nginx/1.12":    ("Nginx 1.12", "Nginx 1.24+"),
    "PHP/5":         ("PHP 5.x",    "PHP 8.2+"),
    "PHP/7.0":       ("PHP 7.0",    "PHP 8.2+"),
    "PHP/7.1":       ("PHP 7.1",    "PHP 8.2+"),
    "OpenSSL/1.0":   ("OpenSSL 1.0","OpenSSL 3.x"),
    "Microsoft-IIS/6.0": ("IIS 6.0", "IIS 10+"),
    "Microsoft-IIS/7.0": ("IIS 7.0", "IIS 10+"),
}

WEAK_HEADERS = {
    "X-Frame-Options":           "Missing clickjacking protection",
    "X-Content-Type-Options":    "Missing MIME-sniffing protection",
    "Strict-Transport-Security": "Missing HSTS header (HTTPS not enforced)",
    "Content-Security-Policy":   "Missing CSP header (XSS risk)",
    "X-XSS-Protection":          "Missing XSS protection header",
    "Referrer-Policy":           "Missing Referrer-Policy header",
}

SEVERITY = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


# ─────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────

def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def banner(text: str, char: str = "=", width: int = 60) -> str:
    return f"\n{char * width}\n  {text}\n{char * width}"


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────
#  MODULE 1 — PORT SCANNER
# ─────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Try to connect to a single port. Returns info dict or None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            service = COMMON_PORTS.get(port, "Unknown")
            risk    = port in RISKY_PORTS
            severity = "HIGH" if risk else "INFO"
            note = ""
            if port == 23:
                note = "Telnet transmits data in plaintext — replace with SSH."
            elif port == 21:
                note = "FTP transmits credentials in plaintext — consider SFTP/FTPS."
            elif port == 5900:
                note = "VNC exposed — ensure strong password and restrict access."
            elif port == 6379:
                note = "Redis exposed without auth — risk of data theft/RCE."
            elif port == 27017:
                note = "MongoDB exposed — verify authentication is enabled."
            elif port == 445:
                note = "SMB exposed — patch for EternalBlue/WannaCry class vulnerabilities."
            return {
                "port": port,
                "service": service,
                "status": "OPEN",
                "severity": severity,
                "note": note,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def run_port_scan(ip: str, ports: dict, timeout: float = 1.0) -> list[dict]:
    """Scan all ports concurrently using threads."""
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_map = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(future_map):
            result = future.result()
            if result:
                results.append(result)
    results.sort(key=lambda x: x["port"])
    return results


# ─────────────────────────────────────────────
#  MODULE 2 — HTTP HEADER ANALYSIS
# ─────────────────────────────────────────────

def fetch_http_headers(target: str) -> tuple[dict, int, str]:
    """
    Fetch HTTP response headers from a target URL.
    Returns (headers_dict, status_code, final_url).
    """
    headers = {}
    status  = 0
    final_url = target

    # Try HTTPS first, fallback to HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}" if not target.startswith("http") else target
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "VulnScanner/1.0 (Python 3.13)"},
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                headers   = dict(resp.headers)
                status    = resp.status
                final_url = resp.url
            return headers, status, final_url
        except urllib.error.HTTPError as e:
            headers   = dict(e.headers)
            status    = e.code
            final_url = url
            return headers, status, final_url
        except Exception:
            continue

    return headers, status, final_url


def analyze_headers(headers: dict) -> list[dict]:
    """Check for missing/weak security headers."""
    findings = []
    header_keys_lower = {k.lower(): v for k, v in headers.items()}

    for header, description in WEAK_HEADERS.items():
        if header.lower() not in header_keys_lower:
            findings.append({
                "header":      header,
                "severity":    "MEDIUM",
                "description": description,
            })

    # Check Server header disclosure
    server = header_keys_lower.get("server", "")
    if server:
        findings.append({
            "header":      "Server",
            "severity":    "LOW",
            "description": f"Server version disclosed: '{server}' — may aid fingerprinting.",
        })

    return findings


# ─────────────────────────────────────────────
#  MODULE 3 — OUTDATED SOFTWARE DETECTION
# ─────────────────────────────────────────────

def detect_outdated_software(headers: dict) -> list[dict]:
    """
    Compare response headers against known outdated
    software signatures.
    """
    findings = []
    raw_headers = " ".join(headers.values())

    for sig, (detected_name, recommended) in OUTDATED_SIGNATURES.items():
        if sig.lower() in raw_headers.lower():
            findings.append({
                "software":    detected_name,
                "severity":    "HIGH",
                "description": f"Outdated version detected: {detected_name}. "
                               f"Upgrade to {recommended}.",
            })
    return findings


# ─────────────────────────────────────────────
#  MODULE 4 — WEAK CONFIGURATION CHECKS
# ─────────────────────────────────────────────

def check_weak_configs(open_ports: list[dict], headers: dict) -> list[dict]:
    """Identify weak/risky configurations from scan results."""
    findings = []

    # Check HTTP without redirect to HTTPS
    port_numbers = {p["port"] for p in open_ports}
    if 80 in port_numbers and 443 not in port_numbers:
        findings.append({
            "check":       "No HTTPS",
            "severity":    "HIGH",
            "description": "Port 80 (HTTP) is open but port 443 (HTTPS) is not. "
                           "Traffic is unencrypted.",
        })

    # Check for anonymous/plaintext protocols
    for p in open_ports:
        if p["port"] in RISKY_PORTS and p["note"]:
            findings.append({
                "check":       f"Risky Port {p['port']} ({p['service']})",
                "severity":    "HIGH",
                "description": p["note"],
            })

    # Check X-Frame-Options
    h_lower = {k.lower(): v for k, v in headers.items()}
    xframe = h_lower.get("x-frame-options", "").upper()
    if xframe and xframe not in ("DENY", "SAMEORIGIN"):
        findings.append({
            "check":       "X-Frame-Options value",
            "severity":    "MEDIUM",
            "description": f"X-Frame-Options is set to '{xframe}' — "
                           "use DENY or SAMEORIGIN.",
        })

    return findings


# ─────────────────────────────────────────────
#  MODULE 5 — REPORT GENERATOR
# ─────────────────────────────────────────────

def count_by_severity(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def generate_report(
    target:          str,
    ip:              str,
    open_ports:      list[dict],
    header_findings: list[dict],
    outdated:        list[dict],
    weak_configs:    list[dict],
    headers:         dict,
    http_status:     int,
) -> str:
    """Build the full vulnerability report as a formatted string."""

    all_findings = header_findings + outdated + weak_configs
    counts = count_by_severity(all_findings + [
        {"severity": p["severity"]} for p in open_ports
    ])

    lines = []

    # ── Title ──
    lines.append("=" * 62)
    lines.append("       VULNERABILITY SCANNER — ASSESSMENT REPORT")
    lines.append("=" * 62)
    lines.append(f"  Target   : {target}")
    lines.append(f"  IP       : {ip}")
    lines.append(f"  Scanned  : {timestamp()}")
    lines.append(f"  HTTP     : {http_status if http_status else 'N/A'}")
    lines.append("=" * 62)

    # ── Summary ──
    lines.append("\n📊  SUMMARY")
    lines.append("-" * 40)
    for sev, icon in SEVERITY.items():
        lines.append(f"  {icon}  {sev:<10}: {counts.get(sev, 0)}")
    total = sum(counts.values())
    lines.append(f"\n  Total findings: {total}")

    # ── Open Ports ──
    lines.append(banner("SECTION 1 — OPEN PORTS", "-", 60))
    if open_ports:
        lines.append(f"  {'PORT':<8} {'SERVICE':<14} {'SEVERITY':<10} NOTE")
        lines.append("  " + "-" * 56)
        for p in open_ports:
            icon = SEVERITY.get(p["severity"], "")
            note = p["note"] if p["note"] else "—"
            lines.append(
                f"  {p['port']:<8} {p['service']:<14} "
                f"{icon} {p['severity']:<8}  {note}"
            )
    else:
        lines.append("  No open ports found in the scanned range.")

    # ── Outdated Software ──
    lines.append(banner("SECTION 2 — OUTDATED SOFTWARE", "-", 60))
    if outdated:
        for i, f in enumerate(outdated, 1):
            icon = SEVERITY.get(f["severity"], "")
            lines.append(f"  [{i}] {icon} {f['severity']} — {f['software']}")
            lines.append(f"      {f['description']}")
    else:
        lines.append("  ✅  No outdated software signatures detected.")

    # ── Security Headers ──
    lines.append(banner("SECTION 3 — SECURITY HEADERS", "-", 60))
    if header_findings:
        for i, f in enumerate(header_findings, 1):
            icon = SEVERITY.get(f["severity"], "")
            lines.append(f"  [{i}] {icon} {f['severity']} — {f['header']}")
            lines.append(f"      {f['description']}")
    else:
        lines.append("  ✅  All security headers present.")

    # ── Weak Configurations ──
    lines.append(banner("SECTION 4 — WEAK CONFIGURATIONS", "-", 60))
    if weak_configs:
        for i, f in enumerate(weak_configs, 1):
            icon = SEVERITY.get(f["severity"], "")
            lines.append(f"  [{i}] {icon} {f['severity']} — {f['check']}")
            lines.append(f"      {f['description']}")
    else:
        lines.append("  ✅  No weak configurations detected.")

    # ── Server Headers Disclosure ──
    lines.append(banner("SECTION 5 — SERVER RESPONSE HEADERS", "-", 60))
    if headers:
        for k, v in sorted(headers.items()):
            lines.append(f"  {k}: {v}")
    else:
        lines.append("  No HTTP headers received.")

    # ── Recommendations ──
    lines.append(banner("RECOMMENDATIONS", "=", 60))
    recs = []
    if counts["HIGH"] > 0 or counts["CRITICAL"] > 0:
        recs.append("🔴 Address HIGH/CRITICAL issues immediately.")
    if any(p["port"] in RISKY_PORTS for p in open_ports):
        recs.append("🟠 Disable or firewall risky services (Telnet, FTP, VNC, etc.).")
    if header_findings:
        recs.append("🟡 Add missing HTTP security headers in your web server config.")
    if outdated:
        recs.append("🟠 Update all server-side software to current stable versions.")
    if not recs:
        recs.append("🟢 No critical issues. Continue regular security audits.")
    for r in recs:
        lines.append(f"  • {r}")

    lines.append("\n" + "=" * 62)
    lines.append("  END OF REPORT — Generated by VulnScanner v1.0 (Python 3.13)")
    lines.append("=" * 62 + "\n")

    return "\n".join(lines)


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print(banner("VULNERABILITY SCANNER v1.0 — Python 3.13.0"))

    # ── Get target from user ──
    if len(sys.argv) > 1:
        target = sys.argv[1].strip()
    else:
        target = input("\n  Enter target (IP or domain, e.g. scanme.nmap.org): ").strip()

    if not target:
        print("  [ERROR] No target provided. Exiting.")
        sys.exit(1)

    # ── Resolve IP ──
    print(f"\n  [*] Resolving target: {target}")
    ip = resolve_target(target)
    if not ip:
        print(f"  [ERROR] Cannot resolve '{target}'. Check the hostname.")
        sys.exit(1)
    print(f"  [+] Resolved to: {ip}")

    # ── Port Scan ──
    print(f"  [*] Scanning {len(COMMON_PORTS)} common ports ...")
    open_ports = run_port_scan(ip, COMMON_PORTS, timeout=1.0)
    print(f"  [+] Open ports found: {len(open_ports)}")

    # ── HTTP Header Fetch ──
    print(f"  [*] Fetching HTTP headers from {target} ...")
    headers, http_status, final_url = fetch_http_headers(target)
    if headers:
        print(f"  [+] HTTP {http_status} — {final_url}")
    else:
        print("  [!] Could not retrieve HTTP headers.")

    # ── Analysis ──
    print("  [*] Analysing headers and software signatures ...")
    header_findings = analyze_headers(headers)
    outdated        = detect_outdated_software(headers)
    weak_configs    = check_weak_configs(open_ports, headers)

    # ── Generate Report ──
    print("  [*] Generating vulnerability report ...\n")
    report = generate_report(
        target, ip, open_ports,
        header_findings, outdated, weak_configs,
        headers, http_status,
    )

    print(report)

    # ── Save Report to File ──
    report_filename = f"vuln_report_{target.replace('.', '_')}_{datetime.date.today()}.txt"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  📄  Report saved to: {report_filename}\n")


if __name__ == "__main__":
    main()
