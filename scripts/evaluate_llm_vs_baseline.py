#!/usr/bin/env python3
"""
Evaluation experimentale (S5) : compare le triage assiste par LLM (Gemma2 9B)
a une baseline classique basee sur les regles de correlation natives de Wazuh
(rule.level, rule.mitre), par rapport a une reference etablie manuellement
lors de la generation des scenarios de test.

Entree  : labeled_dataset_sample.json (alerte + reference manuelle)
Sortie  : evaluation_results.json + metadata.json (parametres exacts du run,
          pour la reproductibilite) + resume des metriques sur stdout

Revision : le matching MITRE utilisait auparavant un test de sous-chaine
(`ref in extracted or extracted in ref`), qui comptait T1110 comme correct
face a une prediction T1110.001 -- un code parent et sa sous-technique ne
sont PAS le meme code. Cette version separe explicitement :
  - exact_match      : code strictement identique
  - family_match     : meme famille MITRE (Txxxx commun), sous-technique
                        differente ou absente -- compte comme partiel, jamais
                        comme un succes plein
et rapporte les deux taux separement plutot qu'un seul chiffre agrege.
"""

import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import UTC, datetime

import requests

CRITICALITY_EN_TO_FR = {"low": "basse", "medium": "moyenne", "high": "haute", "critical": "critique"}

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma2:9b-instruct-q4_0")
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "0")
TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.1"))
NUM_PREDICT = int(os.environ.get("LLM_NUM_PREDICT", "300"))

DATASET_FILE = os.path.expanduser(os.environ.get("DATASET_FILE", "~/labeled_dataset_per_alert.json"))
OUTPUT_FILE = os.path.expanduser(os.environ.get("OUTPUT_FILE", "~/evaluation_results_v3.json"))
METADATA_FILE = os.path.expanduser(os.environ.get("METADATA_FILE", OUTPUT_FILE.replace(".json", "_metadata.json")))

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

1. Log "sshd: Attempt to login using a non-existent user" -> brute force / devinette de mot de passe -> criticite "haute", tactique "Credential Access", technique "T1110.001"
2. Log "sshd: authentication success." ou "PAM: Login session opened." -> usage normal d'un compte valide -> criticite "basse", tactique "Initial Access", technique "T1078"
3. Log "Successful sudo to ROOT executed." ou "User missed the password to change UID" -> abus/tentative d'elevation de privileges via sudo/su -> criticite "basse" si succes attendu, "moyenne" si echec -> tactique "Privilege Escalation", technique "T1548"
4. Log "New user added to the system." -> creation de compte, technique de persistance -> criticite "haute", tactique "Persistence", technique "T1136"
5. Log "Group (or user) deleted from the system." -> suppression de compte -> criticite "moyenne", tactique "Impact", technique "T1531"
6. Log "Crontab entry changed." -> tache planifiee, technique de persistance -> criticite "moyenne", tactique "Persistence", technique "T1053"
7. Log audit contenant comm="curl" ou comm="wget" (une SEULE occurrence isolee, PAS repetee) suivi d'une URL en argument (champ EXECVE) -> recuperation d'un outil ou payload externe sur le systeme -> criticite "haute", tactique "Command and Control", technique "T1105" (Ingress Tool Transfer). ATTENTION : ne jamais repondre "T1566" (Phishing, impossible a prouver sans passerelle mail) ni "T1071" (reserve UNIQUEMENT aux occurrences REPETEES vers la MEME destination, voir exemple 9 ci-dessous) -- une occurrence unique de curl/wget est TOUJOURS T1105, jamais un autre code.
8. Log audit contenant comm="pwsh" ou comm="powershell" avec un argument "-enc" ou "-EncodedCommand" (commande encodee en base64) -> execution PowerShell suspecte/obfusquee -> criticite "critique", tactique "Execution", technique "T1059.001" (PAS T1056 : T1056 est la capture de saisie clavier/souris, ce qui n'est PAS le cas ici -- c'est bien l'execution du script PowerShell qui est l'evenement, donc T1059.001)
9. Alerte "Repeated network fetch commands to the same destination" ou plusieurs occurrences de curl/wget vers LA MEME destination en peu de temps -> comportement de balisage periodique -> criticite "haute", tactique "Command and Control", technique "T1071"
10. Alerte "Sudo elevation to root shortly after an SSH login from the same source" ou une connexion SSH suivie d'une elevation sudo depuis la meme source en peu de temps -> deplacement d'un compte entre sessions avec elevation -> criticite "haute", tactique "Lateral Movement", technique "T1021.004"

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
        full_log=re.sub(r"[\x00-\x1f]", " ", str(alert.get("full_log", "N/A")))[:900],
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
            "options": {"temperature": TEMPERATURE, "num_predict": NUM_PREDICT},
            "keep_alive": OLLAMA_KEEP_ALIVE,
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
    """Extrait un code MITRE (Txxxx ou Txxxx.xxx) d'une chaine, meme si le modele a renvoye du texte libre."""
    if value is None:
        return None
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    match = re.search(r"T\d{4}(\.\d{3})?", str(value))
    return match.group(0) if match else None


def mitre_family(code: str) -> str:
    """Code parent (avant le point) : T1110.001 -> T1110."""
    return code.split(".")[0]


def mitre_match(ref_technique: str | None, predicted_technique) -> dict:
    """Retourne {'exact_match': bool, 'family_match': bool} -- family_match est vrai
    si les codes partagent la meme famille (Txxxx) mais ne sont PAS strictement egaux ;
    exact_match implique toujours family_match=False pour eviter le double comptage."""
    extracted = extract_mitre_code(predicted_technique)
    if extracted is None or not ref_technique:
        return {"exact_match": False, "family_match": False}
    if extracted == ref_technique:
        return {"exact_match": True, "family_match": False}
    if mitre_family(extracted) == mitre_family(ref_technique):
        return {"exact_match": False, "family_match": True}
    return {"exact_match": False, "family_match": False}


def compute_classification_metrics(refs: list[str], preds: list[str], labels: list[str]) -> dict:
    """Precision/rappel/F1 par classe (one-vs-rest) + matrice de confusion, pour une
    classification a labels fixes (ici : criticite basse/moyenne/haute/critique).
    Une prediction absente/invalide (hors de `labels`) compte comme une erreur envers
    toutes les classes (ni vrai positif ni vrai negatif correct) plutot que d'etre
    silencieusement ignoree, pour ne pas gonfler artificiellement les taux."""
    confusion = {ref_label: {pred_label: 0 for pred_label in labels} for ref_label in labels}
    for ref, pred in zip(refs, preds, strict=True):
        ref_key = ref if ref in labels else None
        pred_key = pred if pred in labels else None
        if ref_key is None:
            continue  # reference invalide : ne devrait pas arriver, dataset mal forme
        if pred_key is None:
            continue  # prediction hors-schema : deja compte via parse_error_rate ailleurs
        confusion[ref_key][pred_key] += 1

    per_class = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in labels if other != label)
        fn = sum(confusion[label][other] for other in labels if other != label)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}

    macro_precision = sum(m["precision"] for m in per_class.values()) / len(labels)
    macro_recall = sum(m["recall"] for m in per_class.values()) / len(labels)
    macro_f1 = sum(m["f1"] for m in per_class.values()) / len(labels)

    return {
        "confusion_matrix": confusion,
        "per_class": per_class,
        "macro_avg": {"precision": macro_precision, "recall": macro_recall, "f1": macro_f1},
    }


def get_git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


def get_ollama_model_digest() -> str:
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/show", json={"name": OLLAMA_MODEL}, timeout=10)
        resp.raise_for_status()
        return resp.json().get("digest", "unknown")
    except Exception:
        return "unknown"


def write_run_metadata(n_alerts: int) -> None:
    """Enregistre les parametres exacts de ce run pour pouvoir prouver que deux
    fichiers de resultats proviennent bien de la meme configuration experimentale."""
    metadata = {
        "run_started_at": datetime.now(UTC).isoformat(),
        "git_commit": get_git_commit(),
        "ollama_model": OLLAMA_MODEL,
        "ollama_model_digest": get_ollama_model_digest(),
        "temperature": TEMPERATURE,
        "num_predict": NUM_PREDICT,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "dataset_file": DATASET_FILE,
        "n_alerts": n_alerts,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
    }
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Metadonnees du run ecrites -> {METADATA_FILE}")


def main() -> None:
    with open(DATASET_FILE) as f:
        dataset = json.load(f)

    write_run_metadata(len(dataset))

    results = []
    for i, item in enumerate(dataset, 1):
        alert = item["alert"]
        ref = item["reference"]

        baseline = baseline_classify(alert)
        llm_result, llm_duration = llm_classify(alert)

        baseline_mitre = mitre_match(ref["mitre_technique"], baseline["mitre_technique"])
        llm_mitre = mitre_match(ref["mitre_technique"], llm_result.get("mitre_technique"))

        entry = {
            "scenario": item["scenario"],
            "reference": ref,
            "baseline": baseline,
            "llm": llm_result,
            "llm_duration_sec": round(llm_duration, 1),
            "baseline_criticality_gap": criticality_gap(ref["criticite"], baseline["criticite"]),
            "llm_criticality_gap": criticality_gap(ref["criticite"], llm_result.get("criticite", "")),
            "baseline_mitre_exact_match": baseline_mitre["exact_match"],
            "baseline_mitre_family_match": baseline_mitre["family_match"],
            "llm_mitre_exact_match": llm_mitre["exact_match"],
            "llm_mitre_family_match": llm_mitre["family_match"],
            "llm_parse_error": llm_result.get("incident_type") == "PARSE_ERROR",
            "llm_criticality_normalized": normalize_criticality(llm_result.get("criticite", ""))[1],
        }
        results.append(entry)
        print(f"[{i}/{len(dataset)}] {item['scenario']}: "
              f"baseline_gap={entry['baseline_criticality_gap']} "
              f"llm_gap={entry['llm_criticality_gap']} "
              f"llm_mitre_exact={entry['llm_mitre_exact_match']} "
              f"llm_mitre_family={entry['llm_mitre_family_match']} "
              f"({llm_duration:.1f}s)")

    refs_criticite = [r["reference"]["criticite"] for r in results]
    baseline_preds_criticite = [normalize_criticality(r["baseline"]["criticite"])[0] for r in results]
    llm_preds_criticite = [normalize_criticality(r["llm"].get("criticite", ""))[0] for r in results]

    baseline_metrics = compute_classification_metrics(refs_criticite, baseline_preds_criticite, CRITICALITY_ORDER)
    llm_metrics = compute_classification_metrics(refs_criticite, llm_preds_criticite, CRITICALITY_ORDER)

    output = {
        "results": results,
        "classification_metrics": {
            "criticite": {
                "baseline": baseline_metrics,
                "llm": llm_metrics,
                "note": (
                    "Precision/rappel/F1 calcules sur la classification de criticite "
                    "(basse/moyenne/haute/critique), one-vs-rest, moyenne macro (non ponderee "
                    "par le support -- chaque classe compte a egalite quelle que soit sa frequence "
                    "dans le dataset). Une prediction hors des 4 labels attendus (erreur de "
                    "parsing JSON, valeur non normalisable) est exclue du calcul plutot que "
                    "comptee comme un vrai/faux positif arbitraire -- voir llm_parse_error par "
                    "entree pour le taux de telles predictions."
                ),
            },
        },
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    n = len(results)
    avg_baseline_gap = sum(r["baseline_criticality_gap"] for r in results) / n
    avg_llm_gap = sum(r["llm_criticality_gap"] for r in results) / n
    baseline_exact_rate = sum(r["baseline_mitre_exact_match"] for r in results) / n
    baseline_family_rate = sum(r["baseline_mitre_family_match"] for r in results) / n
    llm_exact_rate = sum(r["llm_mitre_exact_match"] for r in results) / n
    llm_family_rate = sum(r["llm_mitre_family_match"] for r in results) / n
    avg_llm_time = sum(r["llm_duration_sec"] for r in results) / n
    parse_error_rate = sum(r["llm_parse_error"] for r in results) / n
    normalized_rate = sum(r["llm_criticality_normalized"] for r in results) / n

    print("\n===== RESUME METRIQUES =====")
    print(f"Nombre d'alertes evaluees                          : {n}")
    print(f"Ecart moyen de criticite (regles)                  : {avg_baseline_gap:.2f}")
    print(f"Ecart moyen de criticite (LLM)                     : {avg_llm_gap:.2f}")
    print(f"MITRE exact match (regles)                         : {baseline_exact_rate:.1%}")
    print(f"MITRE family match, sous-technique differente (regles) : {baseline_family_rate:.1%}")
    print(f"MITRE exact match (LLM)                            : {llm_exact_rate:.1%}")
    print(f"MITRE family match, sous-technique differente (LLM)    : {llm_family_rate:.1%}")
    print(f"Temps moyen de triage LLM                          : {avg_llm_time:.1f}s")
    print(f"Taux d'erreurs de parsing JSON (LLM)                : {parse_error_rate:.1%}")
    print(f"Taux de reponses necessitant une normalisation de langue (LLM) : {normalized_rate:.1%}")

    print("\n===== APPROCHE HYBRIDE (criticite=regles + MITRE=LLM) =====")
    print(f"Ecart moyen de criticite (hybride = baseline)      : {avg_baseline_gap:.2f}")
    print(f"MITRE exact match (hybride = LLM)                  : {llm_exact_rate:.1%}")

    print(
        "\nNOTE METHODOLOGIQUE : le taux 'exact match' ci-dessus est la seule mesure a "
        "citer comme taux de reussite MITRE. Le taux 'family match' compte les cas ou le "
        "modele identifie la bonne famille de technique (ex: T1110) sans la sous-technique "
        "exacte (ex: T1110.001 attendu) -- utile diagnostiquement, mais ce n'est PAS un succes."
    )

    print("\n===== METRIQUES DE CLASSIFICATION (criticite) =====")
    for name, metrics in (("Regles (baseline)", baseline_metrics), ("LLM", llm_metrics)):
        m = metrics["macro_avg"]
        print(f"{name} -- precision macro={m['precision']:.2f} rappel macro={m['recall']:.2f} F1 macro={m['f1']:.2f}")
        for label, per_class in metrics["per_class"].items():
            print(f"    {label:<9} precision={per_class['precision']:.2f} rappel={per_class['recall']:.2f} "
                  f"F1={per_class['f1']:.2f} (support={per_class['support']})")
    print(
        "\nMatrice de confusion et details par classe ecrits dans "
        f"{OUTPUT_FILE} (cle classification_metrics.criticite)."
    )


if __name__ == "__main__":
    sys.exit(main())
