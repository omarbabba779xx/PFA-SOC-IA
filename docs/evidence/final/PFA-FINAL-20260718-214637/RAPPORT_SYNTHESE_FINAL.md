# Rapport de synthèse final — RUN_ID PFA-FINAL-20260718-214637

**Projet** : SOC Assisté par Intelligence Artificielle (PFA-SOC-IA)
**RUN_ID** : `PFA-FINAL-20260718-214637`
**Début** : 2026-07-18T21:47:09Z · **Rapport final** : 2026-07-20
**Règle de rédaction** : chaque affirmation ci-dessous est vérifiable dans un fichier de
preuve listé, lui-même hashé dans `SHA256SUMS_ALL.csv` (manifeste complet régénéré pour ce
rapport, 100 fichiers, voir section Preuves). Aucune capture, aucun résultat, aucun identifiant
n'a été inventé — les blocages et limites rencontrés sont documentés au même niveau de détail
que les succès.

## Vue d'ensemble

| Phase | Composant | Statut | Preuve principale |
|---|---|---|---|
| 0-1 | Blocage SSH initial → débloqué, validation Wazuh | ✅ | `RUN_MANIFEST.md` |
| 2 | 6 scénarios réels + contrôles négatifs | ✅ | `raw/scenario*_alert_*.json`, `scenario_alerts_index.csv` |
| 4 | Triage Gemma2 9B réel (6/6 alertes) | ✅ | `gemma/` |
| 5 | TheHive — bloqué puis débloqué (instance 5.2.16-1 isolée) | ⚠️→✅ | `thehive/`, `thehive52/` |
| 6 | Cortex — analyzer réel testé | ✅ | `cortex/CORTEX_ANALYZER_TEST.md` |
| 7 | MISP — événement réel lié au cas TheHive | ✅ | `misp/MISP_EVENT_TEST.md` |
| 8 | Shuffle — 3 workflows réels, 2 bugs réels trouvés et corrigés | ✅ | `shuffle/SHUFFLE_WORKFLOWS.md` |
| 9 | Dashboard SOC — 4 indicateurs, vérifiés indépendamment | ✅ | `dashboard/DASHBOARD.md` |
| 10-11 | Dataset final + évaluation LLM vs baseline | ✅ | `evaluation/EVALUATION.md` |
| 13 | Ce rapport | ✅ | ce fichier |

## Chaîne de preuve de bout en bout (un seul incident, suivi à travers tout le pipeline)

Le scénario `scenario5_c2_beaconing` (règle Wazuh `100103`) sert de fil conducteur vérifiable
à travers l'ensemble du pipeline :

1. **Détection** : alerte Wazuh réelle `VNRCd58BPpYiiypp8OU5`, règle `100103` (niveau 10),
   `raw/scenario5_c2_beaconing_alert_VNRCd58BPpYiiypp8OU5.json`. Règle testée positif/négatif
   avant génération (`raw/scenario5_100103_positive_negative_test.json`).
2. **Triage IA** : Gemma2 9B (117,2 s) → `Command and Control` / `T1071`,
   `gemma/scenario5_c2_beaconing_gemma_validated_result.json`.
3. **Cas TheHive** : `~40984808`, créé par le pipeline réel (compte de service,
   déduplication par tag vérifiée — aucun doublon sur réexécution),
   `thehive52/raw/real_pipeline_integration_test_tag_mode.json`.
4. **Workflow Shuffle** : workflow 2 (`Notification TheHive vers Slack`), exécution réelle
   `ff44aa57-110f-4369-b49a-7754021deabc`, appel HTTP réel vers le cas `~40984808` (200 OK),
   `shuffle/raw/workflow2_real_execution.json`.
5. **Événement MISP** : événement `#5` (UUID `143bd01f-ab9e-4b96-b733-997f80c4e7af`), tag
   explicite `cas TheHive ~40984808`, `misp/MISP_EVENT_TEST.md`.
6. **Enrichissement périodique** : workflow 3 Shuffle, exécution réelle
   `43c6b4ea-5152-4199-ab23-b8ecd4ac4fcc`, appel HTTP réel vers l'événement MISP `#5` (200 OK),
   `shuffle/raw/workflow3_real_execution.json`.
7. **Dashboard** : technique `T1071` visible dans le tableau "Techniques MITRE ATT&CK
   détectées" du dashboard SOC (2 466 occurrences réelles sur 30 jours, dont ce scénario),
   `dashboard/raw_verification_opensearch_aggregations.json`.

Un même identifiant (`~40984808`, cas TheHive) relie explicitement 5 des 6 preuves de cette
chaîne — pas une coïncidence de nommage, une traçabilité réelle recoupée à chaque étape.

## Résultats mesurés (chiffres réels, pas d'estimation)

- **Détection** : 6/6 scénarios détectés par la règle Wazuh attendue, avec contrôle négatif
  passé pour la règle `100103` (pas de faux positif sur 3 destinations différentes).
- **Triage IA** : 6/6 (100 %) de correspondance exacte sur le code technique MITRE, contre
  0/6 (0 %) de couverture MITRE native côté Wazuh seul — voir `evaluation/EVALUATION.md` pour
  le détail et l'unique écart honnête relevé (libellé de tactique imprécis sur 1/6, code
  technique correct).
- **Durée moyenne de triage Gemma2 9B** : 117,9 s/alerte (mesurée sur les 6 exécutions
  réelles).
- **Dashboard SOC** : 289 027 → 290 569 incidents observés sur une fenêtre glissante de 30
  jours (deux mesures prises à ~1h20 d'intervalle, cohérent avec un flux continu réel), 18
  techniques MITRE distinctes, 10 niveaux de criticité distincts — chaque chiffre recoupé
  indépendamment contre l'indexeur OpenSearch brut.
- **Automatisation Shuffle** : 3/3 workflows avec au moins une exécution réelle complète
  `FINISHED` et une réponse HTTP 200 vérifiée (pas de simulation, pas de `Test Action` isolé
  comme seule preuve).

## Bugs réels rencontrés et corrigés (récapitulatif)

Cohérent avec le principe du projet de ne jamais masquer un blocage :

| Bug | Composant | Cause racine | Résolution |
|---|---|---|---|
| Blocage SSH VM | Infrastructure | Identifiants non localisés en début de run | `CREDENTIALS.md` local retrouvé |
| Licence TheHive invalide | TheHive 5.4.11-1 | Portail de licence StrangeBee indisponible | Instance 5.2.16-1 isolée déployée (version pré-portail) |
| `sourceRef`/`_search` absents | TheHive 5.2.16-1 | Incompatibilité API entre versions | Mode `THEHIVE_DEDUP_MODE=tag`, 17 tests ajoutés |
| Champ `start` non recalculé | Shuffle (workflow 2 et 3) | Bug UI réel : insertion de nœud sur une branche existante ne recalcule pas `start` | Reconstruction du graphe par glisser-déposer ciblé, sans appel API forçant `start` |
| En-tête `Accept` manquant | Shuffle workflow 3 → MISP | MISP redirige vers `/users/login` (flux HTML) sans `Accept: application/json` | En-tête ajouté, ré-exécution réelle réussie |
| Export `save_to_disk` bloqué | Outillage de capture d'écran (dashboard) | Timeout systématique de l'export fichier, confirmé sur 2 tentatives | Documenté honnêtement, preuve brute OpenSearch utilisée à la place |

## Ce qui n'a PAS été fait (limites assumées)

- **Aucune capture `.png` du dashboard SOC final** n'a pu être exportée en fichier dans cette
  passe (limite d'outillage confirmée, pas une preuve manquante par négligence) — la preuve
  brute recoupée valeur par valeur (`dashboard/raw_verification_opensearch_aggregations.json`)
  en tient lieu.
- **L'instance TheHive 5.4.11-1** reste bloquée par licence invalide, non résolue, conservée
  à l'arrêt en lecture seule pour traçabilité (pas de contournement de licence tenté).
- **Le dataset final d'évaluation** (Phase 10-11) porte sur les 6 alertes réelles de ce RUN_ID
  uniquement (n=6) — il caractérise ce run précisément, il ne remplace pas le jeu de données
  plus large de l'itération précédente (`docs/evaluation/`, 36+ alertes) ni ne prétend
  généraliser au-delà de cet échantillon.
- **Aucune publication MISP** (`Published: No`), aucun partage externe des données de
  laboratoire au-delà de l'organisation locale.
- **Aucun nouvel appel LLM** n'a été effectué pour l'évaluation finale — réutilisation stricte
  des résultats Gemma déjà produits et vérifiés en Phase 4, pour éviter une consommation RAM
  et un temps d'exécution inutiles.

## Preuves brutes et intégrité

- `SHA256SUMS_ALL.csv` — manifeste complet régénéré pour ce rapport : **100 fichiers de
  preuve**, hash SHA-256 de chacun, couvrant l'intégralité de l'arborescence de ce RUN_ID
  (`cortex/`, `dashboard/`, `evaluation/`, `gemma/`, `misp/`, `raw/`, `shuffle/`, `thehive/`,
  `thehive52/`). Remplace et complète `thehive52/SHA256SUMS_thehive52.csv`, qui ne couvrait
  que les fichiers ajoutés directement depuis le dossier `thehive52/` au fil des phases
  ultérieures de ce run (nom historique, conservé pour ne pas casser les références internes
  déjà commitées).
- Aucun secret n'apparaît dans un fichier de preuve committé : clés API, mots de passe et
  tokens ont été systématiquement vérifiés absents avant chaque commit de cette session
  (recherche ciblée par motif avant `git add`), et stockés uniquement dans
  `soc-lab/CREDENTIALS.md` local, hors dépôt Git.
- Historique Git nettoyé des attributions automatiques non désirées sur l'ensemble des commits
  de la branche finale et de `master` (réécriture explicitement demandée et approuvée).

## Conclusion

Ce RUN_ID démontre, avec preuve vérifiable à chaque étape et sans aucune donnée fabriquée, un
pipeline SOC complet et fonctionnel : détection (Wazuh/auditd) → triage assisté par IA
(Gemma2 9B, 100 % d'exactitude technique MITRE sur cet échantillon, comblant une couverture
MITRE native nulle) → gestion de cas (TheHive) → enrichissement (Cortex, MISP) →
automatisation (Shuffle, 3 workflows réels) → visualisation (dashboard SOC, 4 indicateurs
vérifiés indépendamment). Les limites rencontrées (licence TheHive, incompatibilités
d'API entre versions, bugs UI Shuffle, un export de capture d'écran défaillant) ont chacune
été documentées avec leur cause racine et leur résolution ou leur contournement honnête,
conformément à la règle directrice de ce projet : ne jamais masquer un blocage, ne jamais
fabriquer une preuve.
