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
| `evaluation_results_holdout.json` | Renforcement | 36 alertes issues de scénarios non utilisés pour construire le prompt |
| `evaluation_results_rep1.json` / `rep2.json` / `rep3.json` | Renforcement | 3 répétitions du même jeu pour mesurer la variance (température 0.1) |
| `evaluation_results_phishing_gemma.json` | Changement de modèle | Premier lot phishing testé avec Gemma2 9B (Mistral 7B → Gemma2 9B) |
| `evaluation_results_phishing_gemma2.json` | Changement de modèle | Deuxième lot phishing indépendant |
| `evaluation_results_phishing_repro.json` | Changement de modèle | Lot de reproductibilité (3e lot indépendant) |
| `evaluation_results_advanced_gemma.json` | Changement de modèle | 18 alertes combinées (phishing + PowerShell + C2), scénarios avancés |

## Fichiers de données (entrée des scripts ci-dessus)

`labeled_dataset_sample.json`, `labeled_dataset_per_alert.json`,
`labeled_dataset_holdout.json`, `labeled_dataset_advanced.json`,
`labeled_dataset_phishing_fresh.json`, `labeled_dataset_phishing_fresh2.json`,
`labeled_dataset_phishing_repro.json` — jeux d'alertes réelles + référence
manuelle, produits par `scripts/build_labeled_dataset.py`,
`scripts/build_advanced_dataset.py` et les scripts `relabel_*.py`.

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
