"""Tests unitaires pour scripts/evaluate_llm_vs_baseline.py -- en particulier le
matching MITRE (exact vs family), le point le plus critique corrige suite a l'audit :
l'ancienne version comptait T1110.001 comme une correspondance correcte face a une
reference T1110 (sous-chaine), ce qui surestimait le taux de reussite."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from evaluate_llm_vs_baseline import (  # noqa: E402
    compute_classification_metrics,
    criticality_gap,
    extract_mitre_code,
    mitre_family,
    mitre_match,
    normalize_criticality,
    valid_output_coverage,
)

CRITICALITY_LABELS = ["basse", "moyenne", "haute", "critique"]


def test_classification_metrics_perfect_predictions_score_one():
    refs = ["basse", "moyenne", "haute", "critique"]
    metrics = compute_classification_metrics(refs, refs, CRITICALITY_LABELS)
    assert metrics["macro_avg"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    for label in CRITICALITY_LABELS:
        assert metrics["per_class"][label]["precision"] == 1.0
        assert metrics["per_class"][label]["recall"] == 1.0
        assert metrics["confusion_matrix"][label][label] == 1


def test_classification_metrics_confusion_matrix_counts_misclassifications():
    refs = ["haute", "haute", "moyenne"]
    preds = ["haute", "moyenne", "moyenne"]  # 1 vrai positif haute, 1 haute predit moyenne (FN), 1 moyenne correct
    metrics = compute_classification_metrics(refs, preds, CRITICALITY_LABELS)
    assert metrics["confusion_matrix"]["haute"]["haute"] == 1
    assert metrics["confusion_matrix"]["haute"]["moyenne"] == 1
    assert metrics["confusion_matrix"]["moyenne"]["moyenne"] == 1
    # haute : 1 TP, 0 FP, 1 FN -> precision=1.0, rappel=0.5
    assert metrics["per_class"]["haute"]["precision"] == 1.0
    assert metrics["per_class"]["haute"]["recall"] == 0.5
    # moyenne : 1 TP, 1 FP (le "haute" mal classe), 0 FN -> precision=0.5, rappel=1.0
    assert metrics["per_class"]["moyenne"]["precision"] == 0.5
    assert metrics["per_class"]["moyenne"]["recall"] == 1.0


def test_classification_metrics_invalid_prediction_excluded_not_penalized_arbitrarily():
    refs = ["haute"]
    preds = ["PARSE_ERROR"]  # hors du schema de labels attendu
    metrics = compute_classification_metrics(refs, preds, CRITICALITY_LABELS)
    # Aucune case de la matrice de confusion ne doit etre incrementee pour une prediction invalide.
    assert all(v == 0 for row in metrics["confusion_matrix"].values() for v in row.values())
    assert metrics["per_class"]["haute"]["support"] == 0


def test_classification_metrics_class_with_no_support_scores_zero_not_error():
    refs = ["basse", "basse"]
    preds = ["basse", "basse"]
    metrics = compute_classification_metrics(refs, preds, CRITICALITY_LABELS)
    # "critique" n'apparait jamais dans les references : precision/rappel doivent
    # etre 0.0 par convention (pas de ZeroDivisionError).
    assert metrics["per_class"]["critique"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0}


def test_classification_metrics_end_to_end_counts_invalid_prediction_as_false_negative():
    """count_invalid_as_error=True est la mesure a citer comme performance reelle du
    pipeline : une sortie hors-schema doit degrader le rappel de sa classe de reference
    plutot que de disparaitre du calcul (bug signale par l'audit : la docstring precedente
    affirmait deja compter les invalides comme une erreur, mais le code faisait `continue`,
    les excluant silencieusement -- ce test verrouille le comportement corrige)."""
    refs = ["haute", "haute"]
    preds = ["haute", "PARSE_ERROR"]  # 1 correct, 1 hors schema
    metrics = compute_classification_metrics(refs, preds, CRITICALITY_LABELS, count_invalid_as_error=True)
    assert metrics["per_class"]["haute"]["support"] == 2  # les 2 references comptent toujours
    assert metrics["per_class"]["haute"]["recall"] == 0.5  # 1 TP / (1 TP + 1 FN-invalide)
    assert metrics["invalid_predictions_by_true_class"]["haute"] == 1

    # Sans count_invalid_as_error, la meme entree ne penalise pas le rappel (comportement
    # "sorties valides uniquement", documente et distinct, pas silencieux).
    metrics_valid_only = compute_classification_metrics(refs, preds, CRITICALITY_LABELS)
    assert metrics_valid_only["per_class"]["haute"]["recall"] == 1.0
    assert metrics_valid_only["per_class"]["haute"]["support"] == 1


def test_valid_output_coverage():
    assert valid_output_coverage(["basse", "haute", "PARSE_ERROR"], CRITICALITY_LABELS) == 2 / 3
    assert valid_output_coverage([], CRITICALITY_LABELS) == 0.0
    assert valid_output_coverage(["basse"], CRITICALITY_LABELS) == 1.0


def test_mitre_match_exact():
    result = mitre_match("T1110.001", "T1110.001")
    assert result == {"exact_match": True, "family_match": False}


def test_mitre_match_family_only_parent_vs_subtechnique():
    # Le bug corrige : T1110 (reference) vs T1110.001 (predit) ne doit PLUS
    # compter comme exact_match=True.
    result = mitre_match("T1110", "T1110.001")
    assert result["exact_match"] is False
    assert result["family_match"] is True


def test_mitre_match_family_only_subtechnique_vs_parent():
    result = mitre_match("T1110.001", "T1110")
    assert result["exact_match"] is False
    assert result["family_match"] is True


def test_mitre_match_different_family_is_no_match():
    result = mitre_match("T1110", "T1566")
    assert result == {"exact_match": False, "family_match": False}


def test_mitre_match_missing_prediction():
    result = mitre_match("T1110", None)
    assert result == {"exact_match": False, "family_match": False}


def test_mitre_match_missing_reference():
    result = mitre_match(None, "T1110")
    assert result == {"exact_match": False, "family_match": False}


def test_mitre_match_extracts_code_from_free_text():
    result = mitre_match("T1105", "Ingress Tool Transfer (T1105)")
    assert result["exact_match"] is True


def test_mitre_match_list_prediction():
    result = mitre_match("T1105", ["T1105"])
    assert result["exact_match"] is True


def test_extract_mitre_code_none():
    assert extract_mitre_code(None) is None


def test_extract_mitre_code_no_match():
    assert extract_mitre_code("no technique code here") is None


def test_mitre_family():
    assert mitre_family("T1110.001") == "T1110"
    assert mitre_family("T1110") == "T1110"


def test_criticality_gap_exact_match():
    assert criticality_gap("haute", "haute") == 0


def test_criticality_gap_one_level_off():
    assert criticality_gap("moyenne", "haute") == 1


def test_criticality_gap_invalid_prediction_gets_max_penalty():
    assert criticality_gap("basse", "n'importe quoi") == 4


def test_normalize_criticality_english_to_french():
    value, was_normalized = normalize_criticality("high")
    assert value == "haute"
    assert was_normalized is True


def test_normalize_criticality_already_french():
    value, was_normalized = normalize_criticality("haute")
    assert value == "haute"
    assert was_normalized is False


def test_normalize_criticality_empty():
    value, was_normalized = normalize_criticality("")
    assert value == ""
    assert was_normalized is False
