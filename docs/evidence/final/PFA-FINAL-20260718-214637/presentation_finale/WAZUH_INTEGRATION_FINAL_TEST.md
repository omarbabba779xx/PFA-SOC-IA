# Intégration Wazuh — test complémentaire de bout en bout (2026-07-23)

Ce document couvre un run complémentaire demandé explicitement le 2026-07-23, dont l'objectif
était de (1) vérifier que Wazuh — signalé comme absent des captures — est bien intégré et
opérationnel, et (2) fournir une capture d'écran par outil de la chaîne, prise proprement
(sans le halo orange de débogage de l'extension Claude, sans curseur visible).

## Constat de départ

Au moment de démarrer ce test, la pile Wazuh complète (indexer, manager, dashboard) était
arrêtée (`docker ps -a` → `Exited`), faute de RAM disponible sur la VM (10 Go alloués,
plusieurs autres piles actives). Conforme à la contrainte déjà documentée dans le README
principal (section "Architecture du laboratoire").

**Résolution** : arrêt temporaire de `tenzir-node` et des conteneurs MISP (`misp-docker-*`)
pour libérer de la RAM, puis démarrage séquentiel indexer → manager → dashboard.

## 1. Wazuh — détection réelle

Alerte réelle déclenchée par la règle `100103` (C2 beaconing, MITRE `T1071`) via 3 requêtes
identiques vers une même destination (`http://185.220.101.7:8443/beacon`), en respectant
la logique `same_field` de corrélation sur `audit.execve.a3` documentée dans
`local_rules.xml`.

- [`screenshots/01_wazuh_overview.png`](screenshots/01_wazuh_overview.png) — Dashboard Overview, données réelles (agent actif : `soc-lab`, alertes haute sévérité : 32).
- [`screenshots/02_wazuh_alerte_c2_beaconing.png`](screenshots/02_wazuh_alerte_c2_beaconing.png) — Threat Hunting, filtre `rule.id:100103`, alerte réelle avec description MITRE T1071.

## 2. Shuffle — orchestration complète (12 nœuds), configuration détaillée

Le workflow `PFA-FINAL-20260718-214637 - Orchestration complete SOC-IA` (12 nœuds) a été
capturé dans son ensemble, puis nœud par nœud avec la configuration complète visible
(URL, méthode HTTP, corps de requête) :

- [`screenshots/03_shuffle_canvas_complet.png`](screenshots/03_shuffle_canvas_complet.png) — Canvas complet, 12 nœuds.
- [`screenshots/04_shuffle_config_gemma2.png`](screenshots/04_shuffle_config_gemma2.png) — `Http1`, appel Gemma2/Ollama.
- [`screenshots/05_shuffle_config_thehive.png`](screenshots/05_shuffle_config_thehive.png) — `Http5`, création de cas TheHive (jeton Bearer masqué).
- [`screenshots/06_shuffle_config_cortex.png`](screenshots/06_shuffle_config_cortex.png) — `Http6`, appel analyzer Cortex (jeton Bearer masqué).
- [`screenshots/07_shuffle_config_misp.png`](screenshots/07_shuffle_config_misp.png) — `Http misp event`, création d'événement MISP.
- [`screenshots/08_shuffle_config_notification.png`](screenshots/08_shuffle_config_notification.png) — `Http notification`, envoi vers le récepteur externe.
- [`screenshots/09_shuffle_config_low_severity_tag.png`](screenshots/09_shuffle_config_low_severity_tag.png) — `Http low severity tag`, PATCH du cas TheHive pour la branche basse sévérité.

## 2bis. Shuffle — chaque nœud individuellement, y compris les 5 gardes d'échec et leurs conditions

À la demande explicite de l'utilisateur (« je veux que l'encadrant voie le réglage et le rôle
de chaque nœud, même pour les conditions »), capture individuelle des **12 nœuds** du workflow
(7 nœuds métier + 5 gardes d'échec ajoutées dans une session précédente pour détecter les
échecs HTTP silencieux, cf. Section 7 du README) et de **6 conditions** représentatives du
mécanisme de garde :

| Nœud / condition | Capture | Rôle |
|---|---|---|
| `Webhook 1` | [15](screenshots/15_shuffle_config_webhook.png) | Réception de l'alerte Wazuh |
| Condition `$http_1.status larger than 299` | [17](screenshots/17_shuffle_condition_http1_status_gate.png) | Bascule vers `http_gemma2_failed` si Gemma2 échoue |
| Condition `$http_1.status less than 300` | [26](screenshots/26_shuffle_condition_http1_success_path.png) | Chemin normal vers `http_5` (TheHive) si Gemma2 réussit |
| `http_gemma2_failed` | [16](screenshots/16_shuffle_config_http_gemma2_failed.png) | Alerte d'échec si le triage IA échoue (bloquant : bloque toute la suite) |
| Condition `$http_5.status larger than 299` | [19](screenshots/19_shuffle_condition_http5_status_gate.png) | Bascule vers `http_case_creation_failed` si la création du cas TheHive échoue |
| `http_case_creation_failed` | [18](screenshots/18_shuffle_config_http_case_creation_failed.png) | Alerte d'échec création de cas |
| `http_cortex_failed` | [22](screenshots/22_shuffle_config_http_cortex_failed.png) | Alerte d'échec de l'analyzer Cortex (non bloquant) |
| Condition `$http_misp_event.status larger than 299` | [20](screenshots/20_shuffle_condition_misp_status_gate.png) | Bascule vers `http_misp_failed` |
| `http_misp_failed` | [21](screenshots/21_shuffle_config_http_misp_failed.png) | Alerte d'échec création événement MISP |
| Condition `$http_notification.status larger than 299` | [23](screenshots/23_shuffle_condition_notification_status_gate.png) | Bascule vers `http_notification_failed` |
| `http_notification_failed` | [24](screenshots/24_shuffle_config_http_notification_failed.png) | Alerte d'échec de la notification finale |
| `http_low_tag_failed` | [25](screenshots/25_shuffle_config_http_low_tag_failed.png) | Alerte d'échec du tag basse sévérité |

**Preuve qu'une garde se déclenche réellement (pas seulement en théorie)** : lors d'un test
antérieur avec un jeton API TheHive volontairement invalide (exécution
`0310a888-9645-4ac3-8d82-dfbdd1d18f1f`), TheHive a répondu `401 AuthenticationError` — la garde
a correctement basculé vers `http_case_creation_failed` (`SUCCESS`) et tous les nœuds en aval
(`http_6`, `http_misp_event`, `http_low_severity_tag`, `http_notification`) ont été
correctement `SKIPPED`. Données brutes récupérées via l'API Shuffle le 2026-07-23 :
[`gate_trigger_real_execution.json`](gate_trigger_real_execution.json).

## 3. Réexécution avec l'alerte Wazuh réelle

L'alerte C2 beaconing réellement détectée en étape 1 a été injectée dans le workflow Shuffle
via son webhook (et non un payload de test synthétique).

**Limite découverte et non masquée** : sous charge RAM (VM à 10 Go, plusieurs piles actives
simultanément), l'appel à Gemma2/Ollama a dépassé le timeout de 300 s configuré côté Shuffle
(`SHUFFLE_APP_SDK_TIMEOUT`) à deux reprises sur les réexécutions de ce run. Le nœud `Http1`
est marqué `SUCCESS` par Shuffle (la requête HTTP a abouti au niveau transport) mais le corps
de la réponse contient une erreur de timeout applicatif, sans champ `.status` HTTP exploitable.
La porte de garde `http_gemma2_failed` (qui compare `$http_1.status`) ne peut donc pas non
plus détecter ce cas — **elle est évaluée à "0 condition remplie" et se met SKIPPED**, au lieu
de basculer sur la branche d'échec. C'est une extension du problème déjà documenté dans
[`shuffle/orchestration_complete/http_status_gate_fix.json`](../shuffle/orchestration_complete/http_status_gate_fix.json)
(porte basée sur `.status`, invisible aux échecs purement transport/timeout) : non corrigé
dans le temps disponible pour ce run, documenté honnêtement plutôt que masqué.

Plutôt que de retenter indéfiniment sous contrainte RAM, les captures qui suivent proviennent
d'une exécution réelle et complète antérieure de ce même workflow, avec la même alerte type
(escalade de privilèges / sudoers, sévérité critique, `rule_level=12`), déjà vérifiée et
documentée dans
[`shuffle/orchestration_complete/end_to_end_retest.json`](../shuffle/orchestration_complete/end_to_end_retest.json)
(`test_2_baseline_critique_propre`, exécution `48297155-9f5c-412e-90d8-3c9b08f3773b`) :
`http_1` SUCCESS (triage cohérent), `http_5` SUCCESS (cas TheHive réel `~28720`), `http_6`
SUCCESS (job Cortex réel), `http_misp_event` SUCCESS (événement MISP réel), `http_notification`
SUCCESS.

## 4. TheHive — cas réel avec triage Gemma2

- [`screenshots/10_thehive_case22_gemma_triage.png`](screenshots/10_thehive_case22_gemma_triage.png) — Cas `#22` (id interne `~28720`), créé automatiquement par le pipeline (`SOC Pipeline 5.2 Service Account`), sortie brute Gemma2 visible dans la description : `incident_type: Privilege Escalation`, `mitre_technique: T1059`, résumé et recommandation en français générés par le modèle.

## 5. Cortex — enrichissement réel

- [`screenshots/11_cortex_jobs_history.png`](screenshots/11_cortex_jobs_history.png) — Historique des jobs, 12 jobs réels, analyzer `AbuseIPDB_2_0` sur l'IP `185.220.101.7`, tous `Success`.
- [`screenshots/12_cortex_job_report_abuseipdb.png`](screenshots/12_cortex_job_report_abuseipdb.png) — Rapport détaillé d'un job : `Tor: True`, `Usage: Fixed Line ISP`, `Score: 100`, `Reports: 67` — résultat réel de l'API AbuseIPDB.

## 6. MISP — événement réel et IOC

MISP avait été arrêté pour libérer de la RAM plus tôt dans la session ; redémarré
spécifiquement pour cette capture (RAM disponible vérifiée à 4,4 Gi avant redémarrage,
aucun autre service arrêté pour y parvenir).

- [`screenshots/13_misp_event11_header.png`](screenshots/13_misp_event11_header.png) — Événement `#11`, organisation `SOC-LAB-PFA`, créé par le pipeline.
- [`screenshots/14_misp_event11_attribute_ioc.png`](screenshots/14_misp_event11_attribute_ioc.png) — Attribut réel `ip-dst 185.220.101.7`, commentaire `IOC extrait automatiquement du triage Gemma2 (workflow Shuffle)`, IDS activé, corrélé à 4 autres événements.

## Méthode de capture propre (sans halo orange, sans curseur)

Les indicateurs visuels de débogage de l'extension Claude (`#claude-agent-glow-border`,
`#claude-phantom-cursor`) sont injectés dans le DOM de la page par l'extension elle-même —
ce ne sont pas des éléments natifs de Chrome ni de l'OS. Aucune API Windows classique
(`SetCursorPos`, `SendInput`) n'a d'effet dessus. Solution retenue :
[`scripts/clean_screenshot.ps1`](../../../../../scripts/clean_screenshot.ps1) — déplace le
curseur synthétique vers un coin mort via l'action `hover` de l'outil navigateur, prend une
capture d'écran **niveau OS** (`Graphics.CopyFromScreen`, pas une capture CDP) du process
Chrome ciblé, puis rogne la barre d'onglets/favoris et les marges résiduelles.

**Piège rencontré et corrigé pendant ce run** : avec plusieurs onglets ouverts dans la même
fenêtre Chrome, cibler un onglet par `tabId` via l'extension ne change pas forcément l'onglet
visible au niveau OS (`MainWindowTitle` inchangé) — la capture niveau OS capturait alors le
mauvais onglet. Corrigé en ne gardant qu'un seul onglet ouvert à la fois pendant les captures.
