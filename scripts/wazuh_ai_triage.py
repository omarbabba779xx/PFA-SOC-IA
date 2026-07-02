#!/usr/bin/env python3
"""
Pipeline de triage assiste par IA : Wazuh -> Ollama (Mistral 7B) -> TheHive

Recupere les alertes recentes depuis l'indexeur Wazuh, les soumet a un LLM local
pour classification/scoring/mapping MITRE ATT&CK, puis cree automatiquement un
cas TheHive si la criticite estimee depasse un seuil.

Variables d'environnement attendues :
  WAZUH_INDEXER_URL   (defaut: https://localhost:9200)
  WAZUH_INDEXER_USER  (defaut: admin)
  WAZUH_INDEXER_PASSWORD
  OLLAMA_URL          (defaut: http://localhost:11434)
  OLLAMA_MODEL        (defaut: mistral:7b-instruct-q4_0)
  THEHIVE_URL         (defaut: http://localhost:9000)
  THEHIVE_API_KEY
  CRITICALITY_THRESHOLD (defaut: moyenne)
"""

import json
import os
import sys
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b-instruct-q4_0")

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")

CRITICALITY_ORDER = ["basse", "moyenne", "haute", "critique"]
CRITICALITY_THRESHOLD = os.environ.get("CRITICALITY_THRESHOLD", "moyenne")

TRIAGE_PROMPT_TEMPLATE = """Tu es un assistant de triage SOC. Analyse l'alerte suivante et
reponds UNIQUEMENT en JSON valide avec les champs : incident_type, criticite
(basse/moyenne/haute/critique), mitre_tactic, mitre_technique, resume, recommandation.

Alerte Wazuh :
- Regle : {rule_description} (niveau {rule_level})
- Agent : {agent_name}
- Horodatage : {timestamp}
- Extrait log : {log_excerpt}

Reponds uniquement avec le JSON, sans texte autour.
"""


def fetch_recent_alerts(minutes: int = 15, size: int = 20) -> list[dict]:
    """Recupere les alertes Wazuh des N dernieres minutes depuis l'indexeur."""
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat() + "Z"
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"timestamp": {"gte": since}}},
    }
    resp = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def triage_with_llm(alert: dict) -> dict:
    """Soumet une alerte au LLM local et parse la reponse JSON de triage."""
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        rule_description=alert.get("rule", {}).get("description", "N/A"),
        rule_level=alert.get("rule", {}).get("level", "N/A"),
        agent_name=alert.get("agent", {}).get("name", "N/A"),
        timestamp=alert.get("timestamp", "N/A"),
        log_excerpt=str(alert.get("full_log", ""))[:500],
    )
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=180,
    )
    resp.raise_for_status()
    raw_response = resp.json()["response"]
    try:
        return json.loads(raw_response)
    except json.JSONDecodeError:
        start, end = raw_response.find("{"), raw_response.rfind("}") + 1
        return json.loads(raw_response[start:end])


def create_thehive_case(alert: dict, triage: dict) -> str:
    """Cree un cas TheHive a partir du resultat de triage IA. Retourne l'id du cas."""
    criticite = triage.get("criticite", "moyenne").lower()
    mitre_technique = triage.get("mitre_technique", "unknown")
    if isinstance(mitre_technique, list):
        mitre_technique = ", ".join(mitre_technique)
    recommandation = triage.get("recommandation", triage.get("recommendation", "N/A"))

    payload = {
        "title": f"[{criticite.upper()}] {triage['incident_type']}",
        "description": (
            f"{triage['resume']}\n\n"
            f"**Tactique MITRE** : {triage['mitre_tactic']}\n"
            f"**Technique MITRE** : {mitre_technique}\n"
            f"**Recommandation IA** : {recommandation}\n\n"
            f"Genere automatiquement depuis l'alerte Wazuh (agent : "
            f"{alert.get('agent', {}).get('name', 'N/A')})."
        ),
        "severity": {"basse": 1, "moyenne": 2, "haute": 3, "critique": 4}.get(
            criticite, 2
        ),
        "tags": ["wazuh", "triage-ia", mitre_technique],
        "source": "wazuh-ai-triage",
    }
    resp = requests.post(
        f"{THEHIVE_URL}/api/v1/case",
        headers={"Authorization": f"Bearer {THEHIVE_API_KEY}"},
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["_id"]


def main() -> None:
    threshold_idx = CRITICALITY_ORDER.index(CRITICALITY_THRESHOLD)
    alerts = fetch_recent_alerts()
    print(f"[+] {len(alerts)} alerte(s) recuperee(s) depuis Wazuh")

    for alert in alerts:
        triage = triage_with_llm(alert)
        criticite = triage.get("criticite", "basse").lower()
        print(f"  - {triage.get('incident_type')} -> criticite={criticite}")

        if criticite not in CRITICALITY_ORDER:
            criticite = "basse"
        if CRITICALITY_ORDER.index(criticite) >= threshold_idx:
            case_id = create_thehive_case(alert, triage)
            print(f"    -> cas TheHive cree : {case_id}")


if __name__ == "__main__":
    sys.exit(main())
