import json, os

INPUT_FILE = os.path.expanduser('~/labeled_dataset_holdout_raw.json')
OUTPUT_FILE = os.path.expanduser('~/labeled_dataset_holdout.json')

MANUAL_REFERENCE = {
    'Successful sudo to ROOT executed.': {
        'incident_type': 'Elevation de privileges (sudo)', 'criticite': 'basse',
        'mitre_tactic': 'Privilege Escalation', 'mitre_technique': 'T1548',
    },
    'PAM: Login session opened.': {
        'incident_type': 'Ouverture de session', 'criticite': 'basse',
        'mitre_tactic': 'Initial Access', 'mitre_technique': 'T1078',
    },
    'PAM: Login session closed.': {
        'incident_type': 'Fermeture de session', 'criticite': 'basse',
        'mitre_tactic': 'Initial Access', 'mitre_technique': 'T1078',
    },
    'sshd: authentication success.': {
        'incident_type': 'Connexion SSH reussie', 'criticite': 'basse',
        'mitre_tactic': 'Initial Access', 'mitre_technique': 'T1078',
    },
    'New user added to the system.': {
        'incident_type': 'Creation de compte', 'criticite': 'moyenne',
        'mitre_tactic': 'Persistence', 'mitre_technique': 'T1136',
    },
    'New group added to the system.': {
        'incident_type': 'Creation de groupe (lie a la creation de compte)', 'criticite': 'basse',
        'mitre_tactic': 'Persistence', 'mitre_technique': 'T1136',
    },
    'Group (or user) deleted from the system.': {
        'incident_type': 'Suppression de compte', 'criticite': 'basse',
        'mitre_tactic': 'Impact', 'mitre_technique': 'T1531',
    },
    'Crontab entry changed.': {
        'incident_type': 'Modification de tache planifiee', 'criticite': 'basse',
        'mitre_tactic': 'Persistence', 'mitre_technique': 'T1053',
    },
}

def main():
    with open(INPUT_FILE) as f:
        dataset = json.load(f)
    relabeled = []
    unmatched = 0
    for item in dataset:
        desc = item['alert']['rule']['description']
        ref = MANUAL_REFERENCE.get(desc)
        if ref is None:
            unmatched += 1
            continue
        relabeled.append({'scenario': item['scenario'], 'alert': item['alert'], 'reference': ref})
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(relabeled, f, indent=2, default=str)
    print(f'{len(relabeled)} alertes relabellisees, {unmatched} non appariees')

if __name__ == '__main__':
    main()
