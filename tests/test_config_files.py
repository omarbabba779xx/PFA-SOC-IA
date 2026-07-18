"""Verifie que les fichiers de configuration versionnes sont au moins syntaxiquement
valides (XML bien forme, YAML valide) -- attrape les erreurs de copier-coller avant
un deploiement sur la VM, pas une garantie que la logique metier est correcte."""
import os
import xml.etree.ElementTree as ET

import pytest
import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_local_rules_xml_is_well_formed():
    path = os.path.join(REPO_ROOT, "scripts", "local_rules.xml")
    tree = ET.parse(path)
    root = tree.getroot()
    assert root.tag == "group"


def test_local_rules_xml_rule_ids_are_unique():
    path = os.path.join(REPO_ROOT, "scripts", "local_rules.xml")
    tree = ET.parse(path)
    rule_ids = [rule.get("id") for rule in tree.getroot().findall("rule")]
    assert len(rule_ids) == len(set(rule_ids)), f"IDs de regle dupliques : {rule_ids}"


def test_local_rules_xml_every_rule_has_a_description():
    path = os.path.join(REPO_ROOT, "scripts", "local_rules.xml")
    tree = ET.parse(path)
    for rule in tree.getroot().findall("rule"):
        description = rule.find("description")
        assert description is not None and description.text, f"Regle {rule.get('id')} sans description"


@pytest.mark.parametrize(
    "compose_file",
    ["docker/thehive-docker-compose.yml", "docker/cortex-docker-compose.yml"],
)
def test_docker_compose_files_are_valid_yaml(compose_file):
    path = os.path.join(REPO_ROOT, compose_file)
    with open(path) as f:
        parsed = yaml.safe_load(f)
    assert "services" in parsed
