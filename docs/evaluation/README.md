# Fichiers d'évaluation — quel fichier fait autorité

Ce dossier accumule plusieurs runs successifs (itérations de méthodologie,
répétitions pour mesurer la variance, jeux distincts). Ce fichier indique
lesquels sont cités dans le README principal et dans quel ordre lire
l'historique.

## Fichiers officiels (cités dans le README)

| Fichier | Étape | Ce qu'il mesure |
|---|---|---|
| `evaluation_results.json` | Itération 1 | Premier run, prompt initial non affiné (2,6 % de correspondance MITRE LLM — sert de point de départ, pas de résultat final) |
| `evaluation_results_v2.json` | Itération 2 | Sortie JSON forcée, vocabulaire de criticité normalisé |
| `evaluation_results_v3.json` | Itération 3 | Référence par alerte + exemples few-shot — méthodologie stabilisée |
| `evaluation_results_holdout.json` | Renforcement | 36 alertes issues de scénarios non utilisés pour construire le prompt — **⚠️ voir avertissement ci-dessous, 11 des 36 sont des doublons inter-scénarios** |
| `evaluation_results_rep1.json` / `rep2.json` / `rep3.json` | Renforcement | 3 répétitions du même jeu pour mesurer la variance (température 0.1) |
| `evaluation_results_phishing_gemma.json` | Changement de modèle | Premier lot phishing testé avec Gemma2 9B (Mistral 7B → Gemma2 9B) |
| `evaluation_results_phishing_gemma2.json` | Changement de modèle | Deuxième lot phishing indépendant |
| `evaluation_results_phishing_repro.json` | Changement de modèle | Lot de reproductibilité (3e lot indépendant) |

**`evaluation_results_advanced_gemma.json` n'est plus un fichier officiel** — déplacé dans
`legacy/` (suffixe `_contaminated`) le 2026-07-18, calculé sur un dataset contenant 7 alertes
mal labellisées (trafic d'infrastructure locale confondu avec phishing/C2, voir `legacy/README.md`).
Aucun résultat de remplacement n'a encore été produit sur le dataset nettoyé (11 alertes).

## ⚠️ Avertissement holdout : doublons inter-scénarios (dataset corrigé, résultat pas encore rejoué)

Une relecture a révélé que `labeled_dataset_holdout.json` contenait **11 alertes dupliquées**
entre scénarios différents (le même `_id` d'alerte Elasticsearch apparaissait dans deux blocs
de scénario distincts, par exemple `holdout_sudo_typo_then_success` et `holdout_user_onboarding`
partageaient 5 des mêmes alertes). Sur les 36 alertes nominales du holdout, seules 25 étaient
réellement distinctes.

Le fichier `labeled_dataset_holdout.json` a été dédupliqué le 2026-07-18 (36 → 25 alertes,
version avec doublons archivée dans `legacy/labeled_dataset_holdout_with_duplicates.json`).
**`evaluation_results_holdout.json` reste toutefois l'ancien résultat calculé sur les 36
alertes avec doublons** (archivé aussi dans `legacy/evaluation_results_holdout_with_duplicates.json`
pour traçabilité) : le chiffre de 94,4 % cité dans le README principal a donc été mesuré sur un
jeu partiellement redondant, pas sur 25/36 alertes indépendantes. Aucune nouvelle évaluation
n'a été relancée sur le jeu dédupliqué (nécessite Ollama + la VM, indisponibles pendant cette
passe) — ne pas citer 94,4 % comme mesure de généralisation tant qu'un nouveau run sur le
fichier dédupliqué n'a pas été produit.

## Fichiers de données (entrée des scripts ci-dessus)

`labeled_dataset_per_alert.json`, `labeled_dataset_holdout.json`,
`labeled_dataset_advanced.json`, `labeled_dataset_phishing_fresh.json`,
`labeled_dataset_phishing_fresh2.json`, `labeled_dataset_phishing_repro.json`
— jeux d'alertes réelles + référence manuelle, produits par
`scripts/build_labeled_dataset.py`, `scripts/build_advanced_dataset.py` et
les scripts `relabel_*.py`.

**`labeled_dataset_sample.json` n'est PAS un fichier d'entrée officiel** : sa
référence est attribuée par bloc de scénario entier (fenêtre temporelle), pas
par alerte individuelle — un même bloc peut contenir plusieurs types
d'événements différents qui reçoivent tous la même référence, ce qui
contamine le calcul. Il ne sert que d'entrée brute à
`scripts/relabel_per_alert.py`, qui reconstruit une référence propre par
alerte individuelle (`labeled_dataset_per_alert.json`, le fichier réellement
utilisé) — ne jamais citer un chiffre calculé directement sur
`labeled_dataset_sample.json`.

**`labeled_dataset_advanced.json` a été nettoyé le 2026-07-18** : la version
initiale (18 alertes) contenait 7 alertes contaminées par du trafic
d'infrastructure locale (santé Ollama, requêtes indexeur Wazuh) mal
labellisées comme phishing/C2 — voir `legacy/README.md` pour le détail
complet. La version actuelle (11 alertes) est nettoyée mais n'a pas encore
été réévaluée avec le LLM ; les anciens résultats
(`evaluation_results_advanced_gemma.json`, `evaluation_results_advanced_fewshot2.json`)
ont été déplacés dans `legacy/` avec le suffixe `_contaminated` et ne doivent
plus être cités.

## `legacy/`

Fichiers d'une méthodologie de référence antérieure, **contradictoire** avec
la version actuelle (codes MITRE différents pour les mêmes scénarios). Voir
`legacy/README.md` pour le détail. Ne jamais citer un chiffre calculé à
partir de ces fichiers dans le rapport final.

## Comment relancer une évaluation

```bash
export DATASET_FILE=~/labeled_dataset_per_alert.json
export OUTPUT_FILE=~/evaluation_results_v4.json   # ne jamais écraser un fichier officiel existant
python3 scripts/evaluate_llm_vs_baseline.py
```

Le script écrit désormais systématiquement un fichier `..._metadata.json` à
côté du fichier de résultats (commit Git, digest du modèle Ollama,
température, `num_predict`, hash du dataset non calculé pour l'instant —
seule sa taille en nombre d'alertes est enregistrée) : conservez-le, c'est
la preuve que deux runs sont comparables ou non.
