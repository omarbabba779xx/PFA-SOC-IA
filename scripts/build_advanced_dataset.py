import json, os, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_INDEXER_URL = 'https://localhost:9200'
WAZUH_INDEXER_USER = 'admin'
WAZUH_INDEXER_PASSWORD = open(os.path.expanduser('~/.wazuh_indexer_password')).read().strip()

RULE_REFS = {
    '100099': {'incident_type': 'Recuperation de payload suspect (proxy phishing)', 'criticite': 'haute', 'mitre_tactic': 'Initial Access', 'mitre_technique': 'T1566'},
    '100101': {'incident_type': 'Execution PowerShell encodee suspecte', 'criticite': 'critique', 'mitre_tactic': 'Execution', 'mitre_technique': 'T1059.001'},
    '100103': {'incident_type': 'Requetes repetees vers la meme destination (C2 beaconing simule)', 'criticite': 'haute', 'mitre_tactic': 'Command and Control', 'mitre_technique': 'T1071'},
    '100105': {'incident_type': 'Connexions SSH successives avec elevation (mouvement lateral simule)', 'criticite': 'haute', 'mitre_tactic': 'Lateral Movement', 'mitre_technique': 'T1021.004'},
}
SCENARIO_NAMES = {
    '100099': 'phishing_url_proxy',
    '100101': 'powershell_suspicious',
    '100103': 'c2_beaconing_simulated',
    '100105': 'lateral_movement_simulated',
}

labeled = []
for rule_id, ref in RULE_REFS.items():
    query = {
        'size': 5,
        'sort': [{'timestamp': {'order': 'desc'}}],
        'query': {'term': {'rule.id': rule_id}},
    }
    resp = requests.get(f'{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search', auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD), json=query, verify=False, timeout=15)
    hits = resp.json()['hits']['hits']
    for h in hits:
        alert = h['_source']
        # exclude container noise (docker-default) for 100099
        if rule_id == '100099' and alert.get('data', {}).get('audit', {}).get('subj') == 'docker-default':
            continue
        labeled.append({'scenario': SCENARIO_NAMES[rule_id], 'alert': alert, 'reference': ref})

with open('/home/soc/labeled_dataset_advanced.json', 'w') as f:
    json.dump(labeled, f, indent=2, default=str)
print(f'{len(labeled)} alertes reelles collectees pour les 4 scenarios avances')
