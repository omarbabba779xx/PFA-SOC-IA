#!/usr/bin/env python3
"""
Evaluation experimentale (S5) : compare le triage assiste par LLM (Mistral 7B)
a une baseline classique basee sur les regles de correlation natives de Wazuh
(rule.level, rule.mitre), par rapport a une reference etablie manuellement
lors de la generation des scenarios de test.

Entree  : labeled_dataset_sample.json (alerte + reference manuelle)
Sortie  : evaluation_results.json + resume des metriques sur stdout
"""

import json
import os
import re
import sys
import time

import requests

CRITICALITY_EN_TO_FR = {"low": "basse", "medium": "moyenne", "high": "haute", "critical": "critique"}

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b-instruct-q4_0")

DATASET_FILE = os.path.expanduser(os.environ.get("DATASET_FILE", "~/labeled_dataset_per_alert.json"))
OUTPUT_FILE = os.path.expanduser(os.environ.get("OUTPUT_FILE", "~/evaluation_results_v3.json"))

CRITICALITY_ORDER = ["basse", "moyenne", "haute", "critique"]

TRIAGE_PROMPT_TEMPLATE = """Tu es un assistant de triage SOC specialise sur les logs Linux/SSH/PAM.
Analyse l'alerte suivante et reponds UNIQUEMENT en JSON valide avec exactement
les champs suivants :
- incident_type (string, court)
- criticite : un seul mot parmi EXACTEMENT "basse", "moyenne", "haute", "critique" (en francais, jamais en anglais)
- mitre_tactic (string, nom officiel de la tactique MITRE ATT&CK)
- mitre_technique : UNIQUEMENT le code technique officiel au format "Txxxx" (jamais une description ni un nom)
- resume (string)
- recommandation (string)

Voici des exemples de classification correcte pour des alertes similaires (memorise le code MITRE exact associe a chaque type d'evenement) :

1. Log "sshd: Attempt to login using a non-existent user" -> brute force / devinette de mot de passe -> criticite "haute", tactique "Credential Access", technique "T1110"
2. Log "sshd: authentication success." ou "PAM: Login session opened." -> usage normal d'un compte valide -> criticite "basse", tactique "Initial Access", technique "T1078"
3. Log "Successful sudo to ROOT executed." ou "User missed the password to change UID" -> abus/tentative d'elevation de privileges via sudo/su -> criticite "basse" si succes attendu, "moyenne" si echec -> tactique "Privilege Escalation", technique "T1548"
4. Log "New user added to the system." -> creation de compte, technique de persistance -> criticite "haute", tactique "Persistence", technique "T1136"
5. Log "Group (or user) deleted from the system." -> suppression de compte -> criticite "moyenne", tactique "Impact", technique "T1531"
6. Log "Crontab entry changed." -> tache planifiee, technique de persistance -> criticite "moyenne", tactique "Persistence", technique "T1053"

Applique le meme niveau de precision pour l'alerte ci-dessous. Si le log correspond a l'un des exemples ci-dessus, reutilise EXACTEMENT le meme code MITRE.

Alerte Wazuh a analyser :
- Regle : {rule_description} (niveau {rule_level})
- Groupes : {rule_groups}
- Log complet : {full_log}
- Agent : {agent_name}
- Horodatage : {timestamp}

Reponds uniquement avec le JSON, sans texte autour, sans balises markdown.
"""


def baseline_classify(alert: dict) -> dict:
    """Classification baseline : regles de correlation natives de Wazuh (rule.level + rule.mitre)."""
    level = alert.get("rule", {}).get("level", 0)
    if level >= 12:
        criticite = "critique"
    elif level >= 9:
        criticite = "haute"
    elif level >= 5:
        criticite = "moyenne"
    else:
        criticite = "basse"

    mitre = alert.get("rule", {}).get("mitre", {})
    technique_id = mitre.get("id", [None])[0]
    tactic = mitre.get("tactic", [None])[0]

    return {
        "incident_type": alert.get("rule", {}).get("description", "N/A"),
        "criticite": criticite,
        "mitre_tactic": tactic,
        "mitre_technique": technique_id,
    }


def llm_classify(alert: dict) -> tuple[dict, float]:
    """Classification par le LLM local. Retourne (resultat, duree_secondes)."""
    rule = alert.get("rule", {})
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        rule_description=rule.get("description", "N/A"),
        rule_level=rule.get("level", "N/A"),
        rule_groups=", ".join(rule.get("groups", [])),
        full_log=__import__("re").sub(r"[\x00-\x1f]", " ", str(alert.get("full_log", "N/A")))[:900],
        agent_name=alert.get("agent", {}).get("name", "N/A"),
        timestamp=alert.get("timestamp", "N/A"),
    )
    start = time.monotonic()
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # force Ollama a contraindre la sortie a du JSON valide
            "options": {"temperature": 0.1},  # reduit la variabilite/derive du modele
        },
        timeout=300,
    )
    duration = time.monotonic() - start
    resp.raise_for_status()
    raw = resp.json()["response"]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        s, e = raw.find("{"), raw.rfind("}") + 1
        try:
            parsed = json.loads(raw[s:e])
        except (json.JSONDecodeError, ValueError):
            parsed = {"incident_type": "PARSE_ERROR", "criticite": "basse",
                      "mitre_tactic": None, "mitre_technique": None}
    return parsed, duration


def normalize_criticality(value: str) -> tuple[str, bool]:
    """Normalise la criticite (ex: anglais -> francais). Retourne (valeur, a_ete_normalisee)."""
    if not value:
        return "", False
    value_lower = value.lower().strip()
    if value_lower in CRITICALITY_ORDER:
        return value_lower, False
    if value_lower in CRITICALITY_EN_TO_FR:
        return CRITICALITY_EN_TO_FR[value_lower], True
    return value_lower, False


def criticality_gap(ref: str, predicted: str) -> int:
    normalized, _ = normalize_criticality(predicted)
    try:
        return abs(CRITICALITY_ORDER.index(ref.lower()) - CRITICALITY_ORDER.index(normalized))
    except (ValueError, AttributeError):
        return len(CRITICALITY_ORDER)  # penalite max si valeur invalide


def extract_mitre_code(value) -> str | None:
    """Extrait un code MITRE (Txxxx) d'une chaine, meme si le modele a renvoye du texte libre."""
    if value is None:
        return None
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    match = re.search(r"T\d{4}(\.\d{3})?", str(value))
    return match.group(0) if match else None


def mitre_match(ref_technique: str, predicted_technique) -> bool:
    extracted = extract_mitre_code(predicted_technique)
    if extracted is None:
        return False
    return ref_technique in extracted or extracted in ref_technique


def main() -> None:
    with open(DATASET_FILE) as f:
        dataset = json.load(f)

    results = []
    for i, item in enumerate(dataset, 1):
        alert = item["alert"]
        ref = item["reference"]

        baseline = baseline_classify(alert)
        llm_result, llm_duration = llm_classify(alert)

        entry = {
            "scenario": item["scenario"],
            "reference": ref,
            "baseline": baseline,
            "llm": llm_result,
            "llm_duration_sec": round(llm_duration, 1),
            "baseline_criticality_gap": criticality_gap(ref["criticite"], baseline["criticite"]),
            "llm_criticality_gap": criticality_gap(ref["criticite"], llm_result.get("criticite", "")),
            "baseline_mitre_match": mitre_match(ref["mitre_technique"], baseline["mitre_technique"]),
            "llm_mitre_match": mitre_match(ref["mitre_technique"], llm_result.get("mitre_technique")),
            "llm_parse_error": llm_result.get("incident_type") == "PARSE_ERROR",
            "llm_criticality_normalized": normalize_criticality(llm_result.get("criticite", ""))[1],
        }
        results.append(entry)
        print(f"[{i}/{len(dataset)}] {item['scenario']}: "
              f"baseline_gap={entry['baseline_criticality_gap']} "
              f"llm_gap={entry['llm_criticality_gap']} "
              f"llm_mitre_match={entry['llm_mitre_match']} "
              f"({llm_duration:.1f}s)")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, default=str)

    n = len(results)
    avg_baseline_gap = sum(r["baseline_criticality_gap"] for r in results) / n
    avg_llm_gap = sum(r["llm_criticality_gap"] for r in results) / n
    baseline_mitre_rate = sum(r["baseline_mitre_match"] for r in results) / n
    llm_mitre_rate = sum(r["llm_mitre_match"] for r in results) / n
    avg_llm_time = sum(r["llm_duration_sec"] for r in results) / n
    parse_error_rate = sum(r["llm_parse_error"] for r in results) / n
    normalized_rate = sum(r["llm_criticality_normalized"] for r in results) / n

    print("\n===== RESUME METRIQUES =====")
    print(f"Nombre d'alertes evaluees        : {n}")
    print(f"Ecart moyen de criticite (regles) : {avg_baseline_gap:.2f}")
    print(f"Ecart moyen de criticite (LLM)     : {avg_llm_gap:.2f}")
    print(f"Taux de correspondance MITRE (regles) : {baseline_mitre_rate:.1%}")
    print(f"Taux de correspondance MITRE (LLM)     : {llm_mitre_rate:.1%}")
    print(f"Temps moyen de triage LLM          : {avg_llm_time:.1f}s")
    print(f"Taux d'erreurs de parsing JSON (LLM) : {parse_error_rate:.1%}")
    print(f"Taux de reponses necessitant une normalisation de langue (LLM) : {normalized_rate:.1%}")

    print("\n===== APPROCHE HYBRIDE (criticite=regles + MITRE=LLM) =====")
    print(f"Ecart moyen de criticite (hybride = baseline) : {avg_baseline_gap:.2f}")
    print(f"Taux de correspondance MITRE (hybride = LLM)  : {llm_mitre_rate:.1%}")


if __name__ == "__main__":
    sys.exit(main())
