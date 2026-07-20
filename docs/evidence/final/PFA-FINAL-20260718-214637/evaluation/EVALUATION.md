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

## Ce qui n'a PAS été fait

- Aucun nouvel appel à Ollama/Gemma2 n'a été effectué pour cette phase — les prédictions
  proviennent intégralement de la Phase 4 déjà réalisée et vérifiée.
- Aucune régénération du grand jeu de données historique (`docs/evaluation/`) — celui-ci reste
  inchangé, avec ses propres avertissements déjà documentés (déduplication du holdout, dataset
  phishing nettoyé).
- Le script `scripts/evaluate_llm_vs_baseline.py` n'a pas été exécuté tel quel (il nécessite
  `labeled_dataset_per_alert.json` au format spécifique et un accès direct à Ollama depuis la
  VM) — la même logique de comparaison (`exact_match`/`family_match`, pas de correspondance
  par sous-chaîne) a été appliquée manuellement sur le jeu minimal de ce RUN_ID pour éviter une
  réexécution coûteuse en RAM/temps alors que les résultats Gemma existaient déjà.

## Preuves brutes

- `DATASET_FINAL.json` — les 6 entrées complètes (référence, baseline, prédiction, verdicts).
- Sources : `../raw/scenario*_alert_*.json` (baseline `rule.mitre`), `../gemma/scenario*_gemma_validated_result.json` (prédictions), `../scenario_alerts_index.csv` (identifiants et hashes).

Hash dans `../thehive52/SHA256SUMS_thehive52.csv`.
