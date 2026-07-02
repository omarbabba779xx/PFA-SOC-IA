import json
import os
import requests

with open(os.path.expanduser("~/triage_result.json")) as f:
    raw = json.load(f)["response"]

start = raw.find("{")
end = raw.rfind("}") + 1
triage = json.loads(raw[start:end])

with open(os.path.expanduser("~/.thehive_api_key")) as f:
    api_key = f.read().strip()

mitre_technique = triage.get("mitre_technique", "unknown")
if isinstance(mitre_technique, list):
    mitre_technique = ", ".join(mitre_technique)

payload = {
    "title": f"[{triage['criticite'].upper()}] {triage['incident_type']} - Brute force SSH (T1110)",
    "description": (
        f"{triage['resume']}\n\n"
        f"**Tactique MITRE**: {triage['mitre_tactic']}\n"
        f"**Technique MITRE**: {mitre_technique}\n"
        f"**Recommandation IA**: {triage.get('recommendation', triage.get('recommandation'))}\n\n"
        f"Genere automatiquement depuis une alerte Wazuh (agent soc-lab) via triage Mistral 7B local."
    ),
    "severity": {"basse": 1, "moyenne": 2, "haute": 3, "critique": 4}.get(
        triage["criticite"].lower(), 2
    ),
    "tags": ["wazuh", "triage-ia", "T1110", "ssh-bruteforce"],
}

resp = requests.post(
    "http://localhost:9000/api/v1/case",
    headers={"Authorization": f"Bearer {api_key}"},
    json=payload,
    timeout=15,
)
print(resp.status_code)
print(resp.json())
