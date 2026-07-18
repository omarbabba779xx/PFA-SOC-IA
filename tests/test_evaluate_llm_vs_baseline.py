"""Tests unitaires pour scripts/evaluate_llm_vs_baseline.py -- en particulier le
matching MITRE (exact vs family), le point le plus critique corrige suite a l'audit :
l'ancienne version comptait T1110.001 comme une correspondance correcte face a une
reference T1110 (sous-chaine), ce qui surestimait le taux de reussite."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from evaluate_llm_vs_baseline import (  # noqa: E402
    criticality_gap,
    extract_mitre_code,
    mitre_family,
    mitre_match,
    normalize_criticality,
)


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
