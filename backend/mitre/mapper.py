"""AEGIS SOC — MITRE ATT&CK Technique Mapper"""
import json, os
from backend.agents.llm import call_llm_json
from backend.config import settings

# Simplified technique database (loaded once)
_techniques = None

def _load_techniques() -> list[dict]:
    global _techniques
    if _techniques is not None:
        return _techniques
    path = settings.mitre_data_path
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            _techniques = json.load(f)
    else:
        _techniques = _get_builtin_techniques()
    return _techniques

def _get_builtin_techniques() -> list[dict]:
    """Fallback: common ATT&CK techniques hardcoded."""
    return [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
        {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
        {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
        {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
        {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
        {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
        {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1588.001", "name": "Malware", "tactic": "Resource Development"},
    ]

async def map_to_mitre(enrichment_summary: str, alert_type: str) -> list[dict]:
    """Use LLM to map observed indicators to MITRE ATT&CK techniques."""
    techniques = _load_techniques()
    technique_list = json.dumps([{"id": t["id"], "name": t["name"], "tactic": t["tactic"]} for t in techniques])

    try:
        result = await call_llm_json(
            prompt=f"""Map these security findings to MITRE ATT&CK techniques.

Alert Type: {alert_type}
Findings: {enrichment_summary[:1000]}

Available techniques:
{technique_list}

Return JSON array of matched techniques with confidence:
[{{"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access", "confidence": 0.9}}]

Only include techniques with confidence >= 0.5. Max 5 techniques.""",
            system_instruction="You are a MITRE ATT&CK mapping expert. Map observed indicators to the most relevant techniques."
        )
        if isinstance(result, list):
            return result[:5]
    except Exception as e:
        print(f"MITRE Mapper LLM Error: {e}")
    return []
