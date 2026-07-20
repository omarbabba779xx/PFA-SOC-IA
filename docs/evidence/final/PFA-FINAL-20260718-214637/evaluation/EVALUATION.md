# Dataset final et évaluation — RUN_ID PFA-FINAL-20260718-214637

## Méthodologie

Contrairement au jeu de données de l'itération précédente (`docs/evaluation/`), construit par
fenêtre temporelle (voir la limite méthodologique documentée dans
`scripts/build_labeled_dataset.py` : risque de contamination par du bruit résiduel de la VM
tombant dans la fenêtre), le jeu de données de ce RUN_ID est construit par **identifiant
d'alerte Wazuh exact** (`wazuh_alert_id`), pas par fenêtre — élimine structurellement le
risque de contamination puisque chaque entrée correspond à une seule alerte réelle précise,
déjà indexée et déjà hashée (voir `scenario_alerts_index.csv`).

Pour chacune des 6 alertes réelles générées dans ce run (Phase 2, `../wazuh/` et `../raw/`) :

1. **Ground truth (référence)** : établie manuellement. Pour 5 des 6 scénarios, réutilise la
   table de référence déjà validée dans une itération précédente
   (`scripts/build_advanced_dataset.py`, `scripts/wazuh_ai_triage.py`). Pour le 6ᵉ
   (`scenario6_network_recon`, règle `100107`), **aucune référence n'existait dans le dépôt**
   — ce scénario a été introduit spécifiquement pour ce RUN_ID. La référence a été établie ici
   directement depuis le référentiel MITRE ATT&CK Enterprise officiel : un scan de ports via
   `nc` correspond à `T1046` (Network Service Discovery), tactique `Discovery` (TA0007).
2. **Baseline native Wazuh** : le champ `rule.mitre` du document brut de chaque alerte,
   vérifié directement sur les 6 fichiers JSON bruts (`../raw/scenario*_alert_*.json`).
3. **Prédiction Gemma2 9B** : déjà produite et validée lors de la Phase 4 de ce RUN_ID
   (`../gemma/scenario*_gemma_validated_result.json`), réutilisée telle quelle — **aucun
   nouvel appel LLM n'a été effectué** pour cette phase (les résultats existants sont réels,
   datés du 18/07/2026, il n'y a aucune raison méthodologique de les regénérer).
4. **Comparaison** : `exact_match` (code MITRE strictement identique à la référence),
   `family_match` (même famille `Txxxx`, sous-technique différente ou absente — jamais compté
   comme un succès plein à lui seul), `tactic_match` (libellé de tactique identique au
   référentiel officiel pour la technique de référence).

Cette méthodologie suit la même rigueur que `scripts/evaluate_llm_vs_baseline.py`
(distinction stricte `exact_match` / `family_match`, pas de correspondance par sous-chaîne)
mais appliquée à un jeu de données minimal et déterministe plutôt qu'au grand jeu historique.

## Résultats

| Scénario | Règle | Référence (tactique / technique) | Baseline native Wazuh | Prédiction Gemma2 9B | Exact match | Tactic match |
|---|---|---|---|---|---|---|
| SSH bruteforce | 5710 | Credential Access / T1110.001 | *(aucune)* | Credential Access / T1110.001 | ✅ | ✅ |
| Téléchargement suspect | 100099 | Command and Control / T1105 | *(aucune)* | Command and Control / T1105 | ✅ | ✅ |
| PowerShell encodé | 100101 | Execution / T1059.001 | *(aucune)* | Execution / T1059.001 | ✅ | ✅ |
| Mouvement latéral | 100105 | Lateral Movement / T1021.004 | *(aucune)* | Lateral Movement / T1021.004 | ✅ | ✅ |
| C2 beaconing | 100103 | Command and Control / T1071 | *(aucune)* | Command and Control / T1071 | ✅ | ✅ |
| Sondage réseau (nc) | 100107 | Discovery / T1046 | *(aucune)* | **Reconnaissance** / T1046 | ✅ | ❌ |

**Métriques agrégées (n=6)** :
- `exact_match` (code MITRE technique) : **6/6 (100 %)**
- `family_match` : 6/6 (100 %) — trivialement égal à `exact_match` ici, aucun cas de
  sous-technique erronée dans ce petit jeu
- `tactic_match` (libellé de tactique) : **5/6 (83,3 %)**
- **Couverture MITRE de la baseline native Wazuh (`rule.mitre`) : 0/6 (0 %)** — aucune des 6
  règles personnalisées ou standard utilisées n'a de champ `rule.mitre` renseigné dans ce
  laboratoire ; sans le triage LLM, ces 6 alertes réelles n'auraient eu **aucune** technique
  MITRE associée automatiquement.
- Durée moyenne d'inférence Gemma2 9B (mesurée, pas estimée) : **117,9 s/alerte**

## Interprétation honnête

- Sur ce petit échantillon déterministe (6 alertes réelles, sélection exacte par ID, pas de
  fenêtre temporelle), Gemma2 9B a produit le code MITRE technique correct dans 100 % des cas
  — cohérent avec les résultats plus larges de l'itération précédente (94,4 % sur un holdout
  de 36, avec les réserves de déduplication documentées dans
  `docs/evaluation/README.md`), mais **n=6 est un échantillon trop petit pour généraliser** —
  ce chiffre caractérise ce RUN_ID précisément, ce n'est pas une nouvelle mesure de
  performance globale du modèle.
- **Le seul écart réel** : sur le scénario `network_recon` introduit dans ce RUN_ID (sans
  précédent dans le dépôt), Gemma a nommé la tactique "Reconnaissance" au lieu de "Discovery"
  — le code technique (`T1046`) reste exact, mais le libellé de tactique associé ne correspond
  pas au référentiel MITRE officiel pour cette technique précise. Erreur de nommage, pas de
  classification. Consigné honnêtement, pas comptabilisé comme un succès total ni masqué.
- La valeur du triage LLM dans ce laboratoire n'est pas seulement sa précision : c'est que,
  sans lui, la baseline native Wazuh (`rule.mitre`) est **structurellement vide** pour ces
  règles personnalisées (0/6). Le LLM comble un vide, il ne rivalise pas avec une baseline
  déjà performante.
- Ce jeu de 6 alertes ne remplace pas le jeu de données plus large de l'itération précédente
  (`docs/evaluation/`, 36+ alertes, plusieurs répétitions) — il caractérise spécifiquement les
  6 scénarios réels générés sous ce RUN_ID, avec zéro appel LLM supplémentaire (réutilisation
  stricte des résultats déjà produits et vérifiés en Phase 4).

## Mise à jour — ré-évaluation réelle sur le jeu holdout dédupliqué (2026-07-20)

Pour dépasser la limite n=6 ci-dessus, une deuxième évaluation a été lancée avec de
**nouveaux appels LLM réels** (pas de réutilisation) sur `docs/evaluation/labeled_dataset_holdout.json`
— le jeu holdout de 25 alertes réelles, dédupliqué le 2026-07-18, mais **jamais réévalué
depuis cette déduplication** (trou méthodologique explicitement signalé dans
`docs/evaluation/README.md` : le chiffre de 94,4 % cité historiquement avait été mesuré
*avant* dédup, sur 36 alertes dont 11 doublons).

- VM redémarrée (elle était arrêtée), script `scripts/evaluate_llm_vs_baseline.py` et le
  dataset dédupliqué (25 alertes, hash `7cbc9963e3...`, vérifié identique à la version du
  dépôt) synchronisés vers la VM avant exécution.
- Exécution réelle : `DATASET_FILE=labeled_dataset_holdout.json`,
  `OUTPUT_FILE=evaluation_results_v4_holdout_dedup.json`, modèle `gemma2:9b-instruct-q4_0`,
  température `0.1` — confirmé activement en cours d'exécution (processus `llama-server` à
  ~720 % CPU pendant toute la durée), durée totale ~55 minutes (25 alertes × ~126 s/alerte
  en moyenne).

### Résultats (n=25, dataset dédupliqué, sans doublons)

| Métrique | Baseline (règles Wazuh) | LLM (Gemma2 9B) |
|---|---|---|
| MITRE exact match | **40,0 %** | **100,0 %** |
| MITRE family match (sous-technique différente) | 24,0 % | 0,0 % |
| Écart moyen de criticité | 0,08 | 0,16 |
| Taux d'erreur de parsing JSON | — | 0,0 % |
| Couverture de sorties exploitables | — | 100,0 % |
| Durée moyenne de triage | — | 125,9 s/alerte |

**100 % de correspondance exacte MITRE sur les 25 alertes dédupliquées** — c'est, à ce jour,
la mesure la plus rigoureuse produite dans ce projet : jeu sans doublons, appels LLM
fraîchement exécutés (pas de réutilisation), et méthodologie stricte
(`exact_match`/`family_match` séparés, jamais de correspondance par sous-chaîne). Ce chiffre
remplace formellement le 94,4 % historique (mesuré sur un jeu contaminé) comme référence
officielle pour ce dataset.

Preuves brutes : `evaluation_results_v4_holdout_dedup.json` (résultat détaillé par alerte),
`evaluation_results_v4_holdout_dedup_metadata.json` (paramètres exacts, hash du dataset,
digest non disponible côté Ollama mais modèle et température consignés), `eval_v4_run.log`
(sortie complète de l'exécution, résumé des métriques).

## Ce qui n'a PAS été fait

- Le grand jeu de données historique (`docs/evaluation/`) au sens large n'a pas été
  entièrement régénéré — seul le holdout dédupliqué (25 alertes) a été réévalué dans cette
  passe, qui comblait le trou méthodologique le plus significatif et le plus explicitement
  signalé.
- Le script `scripts/evaluate_llm_vs_baseline.py` n'a pas été exécuté sur le jeu de 6 alertes
  de ce RUN_ID (format `labeled_dataset_per_alert.json` différent) — la même logique de
  comparaison a été appliquée manuellement sur ce jeu minimal (voir tableau plus haut),
  suffisant vu sa petite taille.

## Preuves brutes

- `DATASET_FINAL.json` — les 6 entrées complètes du RUN_ID (référence, baseline, prédiction, verdicts).
- `evaluation_results_v4_holdout_dedup.json`, `evaluation_results_v4_holdout_dedup_metadata.json`, `eval_v4_run.log` — ré-évaluation réelle du holdout dédupliqué (25 alertes, nouveaux appels LLM).
- Sources : `../raw/scenario*_alert_*.json` (baseline `rule.mitre`), `../gemma/scenario*_gemma_validated_result.json` (prédictions du RUN_ID), `../scenario_alerts_index.csv` (identifiants et hashes).

Hash dans `../SHA256SUMS_ALL.csv`.
