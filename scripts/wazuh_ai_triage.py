#!/usr/bin/env python3
"""
Pipeline de triage assiste par IA : Wazuh -> Ollama (Mistral 7B) -> TheHive

Recupere les alertes recentes depuis l'indexeur Wazuh, applique un triage a
deux niveaux :
  1. Baseline a regles (rule.level) : filtre immediat, sans LLM, qui ecarte
     le bruit et fournit la criticite de reference.
  2. LLM (Mistral 7B) : invoque UNIQUEMENT sur les alertes deja remontees
     par la baseline (rule.level >= LLM_INVOCATION_THRESHOLD_LEVEL), pour
     l'enrichissement (mapping MITRE, resume, recommandation).

La criticite finale utilisee pour la creation du cas TheHive est celle de la
baseline (hybride), le LLM ne fournissant que le mapping MITRE et le contexte
narratif -- voir la section "Re-verification" du README pour la justification
(le LLM seul est moins fiable que la baseline sur la seule tache de scoring
de criticite, mais nettement meilleur sur le mapping MITRE).

Variables d'environnement attendues :
  WAZUH_INDEXER_URL   (defaut: https://localhost:9200)
  WAZUH_INDEXER_USER  (defaut: admin)
  WAZUH_INDEXER_PASSWORD
  OLLAMA_URL          (defaut: http://localhost:11434)
  OLLAMA_MODEL        (defaut: gemma2:9b-instruct-q4_0)
  THEHIVE_URL         (defaut: http://localhost:9000)
  THEHIVE_API_KEY
  CRITICALITY_THRESHOLD (defaut: moyenne) -- seuil de creation de cas
  LLM_INVOCATION_THRESHOLD_LEVEL (defaut: 8) -- rule.level minimum pour invoquer le LLM
                                  (complementaire de Shuffle, qui gere le niveau 5-7 -- voir README)
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
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma2:9b-instruct-q4_0")

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")

CRITICALITY_ORDER = ["basse", "moyenne", "haute", "critique"]
CRITICALITY_NORMALIZE = {
    "low": "basse", "basse": "basse", "faible": "basse",
    "medium": "moyenne", "moyenne": "moyenne", "moyen": "moyenne",
    "high": "haute", "haute": "haute", "eleve": "haute", "élevée": "haute",
    "critical": "critique", "critique": "critique",
}
CRITICALITY_THRESHOLD = os.environ.get("CRITICALITY_THRESHOLD", "moyenne")
LLM_INVOCATION_THRESHOLD_LEVEL = int(os.environ.get("LLM_INVOCATION_THRESHOLD_LEVEL", "8"))

TRIAGE_PROMPT_TEMPLATE = """Tu es un assistant de triage SOC. Analyse l'alerte suivante et
reponds UNIQUEMENT en JSON valide avec les champs : incident_type, criticite
(basse/moyenne/haute/critique), mitre_tactic, mitre_technique, resume, recommandation.

Voici des exemples de classification correcte pour des alertes similaires (memorise le code MITRE exact associe a chaque type d'evenement) :

1. Log "sshd: Attempt to login using a non-existent user" -> brute force / devinette de mot de passe -> criticite "haute", tactique "Credential Access", technique "T1110"
2. Log "sshd: authentication success." ou "PAM: Login session opened." -> usage normal d'un compte valide -> criticite "basse", tactique "Initial Access", technique "T1078"
3. Log "Successful sudo to ROOT executed." ou "User missed the password to change UID" -> abus/tentative d'elevation de privileges via sudo/su -> criticite "basse" si succes attendu, "moyenne" si echec -> tactique "Privilege Escalation", technique "T1548"
4. Log "New user added to the system." -> creation de compte, technique de persistance -> criticite "haute", tactique "Persistence", technique "T1136"
5. Log "Group (or user) deleted from the system." -> suppression de compte -> criticite "moyenne", tactique "Impact", technique "T1531"
6. Log "Crontab entry changed." -> tache planifiee, technique de persistance -> criticite "moyenne", tactique "Persistence", technique "T1053"
7. Log audit contenant comm="curl" ou comm="wget" (une SEULE occurrence isolee, PAS repetee) suivi d'une URL en argument -> recuperation d'un outil ou payload externe -> criticite "haute", tactique "Command and Control", technique "T1105" (Ingress Tool Transfer). ATTENTION : jamais "T1566" (Phishing, impossible a prouver sans passerelle mail) ni "T1071" (reserve aux occurrences REPETEES, voir exemple 9) -- une occurrence unique est TOUJOURS T1105.
8. Log audit contenant comm="pwsh" ou comm="powershell" avec un argument "-enc" ou "-EncodedCommand" -> execution PowerShell suspecte/obfusquee -> criticite "critique", tactique "Execution", technique "T1059.001" (PAS T1056, qui concerne la capture de saisie clavier)
9. Alerte "Repeated network fetch commands executed in a short window" -> requetes repetees vers la meme destination -> balisage periodique -> criticite "haute", tactique "Command and Control", technique "T1071"
10. Alerte "Multiple successive SSH sessions followed by privilege escalation" -> connexions SSH repetees avec elevation -> deplacement entre sessions -> criticite "haute", tactique "Lateral Movement", technique "T1021.004"

Applique le meme niveau de precision pour l'alerte ci-dessous. Si le log correspond a l'un des exemples ci-dessus, reutilise EXACTEMENT le meme code MITRE.

Alerte Wazuh :
- Regle : {rule_description} (niveau {rule_level})
- Agent : {agent_name}
- Horodatage : {timestamp}
- Extrait log : {log_excerpt}

Reponds uniquement avec le JSON, sans texte autour.
"""


def fetch_recent_alerts(minutes: int = 15, size: int = 300, min_level: int | None = None) -> list[dict]:
    """Recupere les alertes Wazuh des N dernieres minutes depuis l'indexeur.

    Filtre par rule.level cote serveur (min_level) plutot que de recuperer
    les N alertes les plus recentes puis filtrer localement : sur une VM au
    volume de bruit eleve, un filtrage client-side peut faire disparaitre les
    alertes significatives (mais peu frequentes) hors de la fenetre avant
    meme d'atteindre le script -- bug reel decouvert et corrige en session
    (voir README, "Decouverte : volume de bruit auditd").
    """
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat() + "Z"
    must = [{"range": {"timestamp": {"gte": since}}}]
    if min_level is not None:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": must}},
    }
    resp = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def baseline_criticality(alert: dict) -> str:
    """Criticite baseline derivee de rule.level (meme logique que l'evaluation S5)."""
    level = alert.get("rule", {}).get("level", 0)
    if level >= 12:
        return "critique"
    if level >= 9:
        return "haute"
    if level >= 5:
        return "moyenne"
    return "basse"


def triage_with_llm(alert: dict) -> dict:
    """Soumet une alerte au LLM local et parse la reponse JSON de triage."""
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        rule_description=alert.get("rule", {}).get("description", "N/A"),
        rule_level=alert.get("rule", {}).get("level", "N/A"),
        agent_name=alert.get("agent", {}).get("name", "N/A"),
        timestamp=alert.get("timestamp", "N/A"),
        log_excerpt=__import__("re").sub(r"[\x00-\x1f]", " ", str(alert.get("full_log", "")))[:900],
    )
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
            "keep_alive": "30m",
        },
        timeout=600,
    )
    resp.raise_for_status()
    raw_response = resp.json()["response"]
    try:
        return json.loads(raw_response)
    except json.JSONDecodeError:
        try:
            start, end = raw_response.find("{"), raw_response.rfind("}") + 1
            return json.loads(raw_response[start:end])
        except json.JSONDecodeError:
            return {"incident_type": "erreur_parsing", "criticite": "basse", "mitre_tactic": "", "mitre_technique": "", "resume": raw_response[:200], "recommandation": ""}


def create_thehive_case(alert: dict, triage: dict, criticite: str) -> str:
    """Cree un cas TheHive. La criticite (severity) provient de la baseline
    (approche hybride) ; le LLM fournit uniquement le mapping MITRE et le
    contexte narratif (resume, recommandation)."""
    payload = {
        "title": f"[{criticite.upper()}] {triage.get('incident_type','')}",
        "description": (
            f"{triage.get('resume','')}\n\n"
            f"**Tactique MITRE** : {triage.get('mitre_tactic','')}\n"
            f"**Technique MITRE** : {triage.get('mitre_technique','')}\n"
            f"**Recommandation IA** : {triage.get('recommandation','')}\n\n"
            f"Genere automatiquement depuis l'alerte Wazuh (agent : "
            f"{alert.get('agent', {}).get('name', 'N/A')})."
        ),
        "severity": {"basse": 1, "moyenne": 2, "haute": 3, "critique": 4}.get(criticite, 2),
        "tags": ["wazuh", "triage-ia", triage.get("mitre_technique", "unknown")],
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
    alerts = fetch_recent_alerts(min_level=LLM_INVOCATION_THRESHOLD_LEVEL)
    print(f"[+] {len(alerts)} alerte(s) recuperee(s) depuis Wazuh")

    llm_invoked, filtered_by_baseline = 0, 0
    for alert in alerts:
        try:
            level = alert.get("rule", {}).get("level", 0)
            criticite = baseline_criticality(alert)

            if level < LLM_INVOCATION_THRESHOLD_LEVEL:
                filtered_by_baseline += 1
                print(f"  - rule.level={level} < seuil {LLM_INVOCATION_THRESHOLD_LEVEL} -> filtre par la baseline (LLM non invoque)")
                continue

            triage = triage_with_llm(alert)
            llm_invoked += 1
            print(f"  - {triage.get('incident_type')} -> criticite (hybride/baseline)={criticite}")

            if CRITICALITY_ORDER.index(criticite) >= threshold_idx:
                case_id = create_thehive_case(alert, triage, criticite)
                print(f"    -> cas TheHive cree : {case_id}")
        except Exception as e:
            print(f"  - [ERREUR sur cette alerte, on continue] {e}")
            continue

    print(f"[+] Resume : {llm_invoked} alerte(s) soumise(s) au LLM, {filtered_by_baseline} filtree(s) par la baseline (bruit, rule.level < {LLM_INVOCATION_THRESHOLD_LEVEL})")


if __name__ == "__main__":
    sys.exit(main())
