# Manifeste de preuves — relier captures, cas et données brutes

Ce fichier relie chaque scénario documenté dans le README à son cas TheHive,
sa règle Wazuh et ses captures d'écran. Les champs marqués `(à renseigner)`
n'ont pas été extraits des logs bruts de la VM au moment de la rédaction de
ce manifeste (les captures elles-mêmes montrent ces informations à l'écran,
mais elles n'avaient pas été copiées dans un fichier structuré séparé) — les
compléter à partir des exports TheHive/Wazuh réels avant de citer ce fichier
comme preuve d'audit indépendante des captures.

## Scénarios du cahier des charges (README, section "Preuve de bout en bout")

| Champ | Brute force SSH | Phishing | PowerShell | Mouvement latéral | C2 beaconing |
|---|---|---|---|---|---|
| Scénario | ssh_bruteforce | phishing_url_proxy | powershell_suspicious | lateral_movement_simulated | c2_beaconing_simulated |
| Technique MITRE | T1110 (T1110.001 après uniformisation) | T1105 | T1059.001 | T1021.004 | T1071 |
| Règle Wazuh | 5710 | 100099 | 100101 | 100105 | 100103 |
| Niveau | 5 | 8 | 12 | 10 | 10 |
| Alert ID (Elasticsearch) | (à renseigner) | (à renseigner) | (à renseigner) | (à renseigner) | (à renseigner) |
| Timestamp | (à renseigner) | (à renseigner) | (à renseigner) | (à renseigner) | (à renseigner) |
| Script de triage | `scripts/triage_single_alert.py 5710` | `scripts/wazuh_ai_triage.py` (auto) | `scripts/wazuh_ai_triage.py` (auto) | `scripts/wazuh_ai_triage.py` (auto) | `scripts/wazuh_ai_triage.py` (auto) |
| Case ID TheHive | #2168 | #2144 | #2151 | #2150 | #2145 |
| Cortex Job ID | (à renseigner) | (à renseigner) | n/a — pas d'observable réseau | (à renseigner) | (à renseigner) |
| Cortex — observable | 127.0.0.1 (AbuseIPDB_2_0) | phishing-simulated-payload.example.invalid (VirusTotal_GetReport_3_1, échec attendu TLD .invalid) | — | 10.0.2.2 (AbuseIPDB_2_0) | c2-beacon-simulated.example.invalid (VirusTotal_GetReport_3_1, échec attendu TLD .invalid) |
| MISP Event ID | n/a — pas de push automatique sur ce lot (voir README, bug TheHive→MISP 403 non résolu) | n/a | n/a | n/a | n/a |
| Captures (docs/screenshots/) | 28, 37, 38 | 32, 33, 39 | 29, 34 | 30, 35, 40 | 31, 36, 41 |
| Git commit au moment de la capture | (à renseigner — voir `git log --oneline -- docs/screenshots/28_*.png`) | idem | idem | idem | idem |

## Incident unique 1.1.1.1 (README, section "Approfondissement")

| Champ | Valeur |
|---|---|
| Source | 1.1.1.1 |
| Alerte reconnaissance | Règle 100107, niveau 6, chemin Shuffle |
| Alerte récupération d'outil | Règle 100099, niveau 8, chemin Gemma |
| Case ID TheHive (Shuffle) | #1344 |
| Case ID TheHive (Gemma) | #2134 |
| Cortex — observable | 1.1.1.1 (AbuseIPDB_2_0) |
| MISP Event ID | référence explicite au cas #1344 dans le commentaire de l'attribut `ip-src` (ID d'événement MISP à renseigner) |
| Captures | 21, 22, 23, 24, 25, 26, 27 |

## Comment compléter ce manifeste

```bash
# Alert ID + timestamp exacts depuis l'indexeur Wazuh :
curl -sk -u admin:$WAZUH_INDEXER_PASSWORD \
  "https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"rule.id":"5710"}},"sort":[{"timestamp":"desc"}],"size":1}' \
  | python3 -m json.tool

# Cortex Job ID depuis l'API Cortex (necessite une cle API, voir CREDENTIALS.md local) :
curl -s -H "Authorization: Bearer $CORTEX_API_KEY" http://127.0.0.1:9001/api/job \
  | python3 -m json.tool

# Git commit au moment d'une capture donnee :
git log --oneline --follow -- docs/screenshots/28_wazuh_alert_5710_bruteforce_ssh.png
```
