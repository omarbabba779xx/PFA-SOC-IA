# Fichiers archivés — méthodologie obsolète, ne pas citer

Ces fichiers correspondent à une version antérieure de la méthodologie de
référence et **contredisent** la version actuelle utilisée par
`scripts/relabel_per_alert.py`, `scripts/relabel_holdout.py` et
`scripts/build_advanced_dataset.py`. Ils sont conservés pour la traçabilité
de la démarche expérimentale (voir README, section "Parcours expérimental"),
mais ne doivent **jamais** être utilisés pour calculer ou citer un chiffre
dans le rapport final.

## Pourquoi ils sont contradictoires

- `reference_advanced.jsonl` classe le scénario phishing en tactique
  `Initial Access` / technique `T1566` (Phishing). La méthodologie actuelle
  (voir le prompt dans `scripts/wazuh_ai_triage.py` et
  `scripts/evaluate_llm_vs_baseline.py`) classe volontairement ce même
  scénario en `Command and Control` / `T1105` (Ingress Tool Transfer),
  parce que l'événement observé est une récupération de payload par
  commande, pas la réception d'un e-mail — `T1566` ne peut pas être prouvé
  sans passerelle mail dans ce laboratoire.
- `reference_dataset.jsonl` classe le brute force SSH en tactique
  `Initial Access`. `scripts/relabel_per_alert.py` le classe en
  `Credential Access`, qui est la tactique MITRE ATT&CK officielle pour la
  technique T1110 (Brute Force).
- `evaluation_results_advanced.json` est un résultat d'évaluation calculé
  avec `reference_advanced.jsonl` (donc avec les codes MITRE obsolètes
  ci-dessus) — les chiffres qu'il contient ne sont pas comparables aux
  résultats produits avec la méthodologie actuelle.
- `reference_holdout.jsonl` est une version antérieure de
  `labeled_dataset_holdout.json` (le fichier réellement utilisé), conservée
  ici pour référence historique uniquement.

## Quels fichiers sont réellement officiels

Voir `docs/evaluation/README.md` (dossier parent) pour la liste des fichiers
qui alimentent effectivement les chiffres cités dans le README principal.
