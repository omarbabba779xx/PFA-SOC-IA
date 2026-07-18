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

## Contamination confirmée du jeu de données "avancé" (2026-07)

`labeled_dataset_advanced_contaminated.json` est la version **initialement
utilisée** pour produire `evaluation_results_advanced_gemma_contaminated.json`
et `evaluation_results_advanced_fewshot2_contaminated.json` (également
archivés ici). Une relecture manuelle du contenu de `full_log` a confirmé
qu'elle contenait 7 alertes sur 18 qui ne correspondent PAS aux scénarios
d'attaque simulés :

- 5 alertes labellisées `phishing_url_proxy` / `T1105` / criticité "haute"
  sont en réalité des appels `curl` locaux vers `http://localhost:11434/api/tags`
  (vérification de disponibilité d'Ollama) ou `https://localhost:9200/...`
  (requêtes vers l'indexeur Wazuh) — du trafic d'infrastructure du
  laboratoire lui-même, pas une tentative de récupération de payload externe.
- 2 alertes labellisées `c2_beaconing_simulated` / `T1071` / criticité "haute"
  sont les mêmes types d'appels locaux.

Ces alertes ont été captées par les anciennes règles Wazuh (trop permissives
avant la correction documentée dans le README — voir "Révision" de la règle
100099/100103) puis intégrées telles quelles dans le dataset par le script de
collecte, sans filtrage des appels internes du pipeline de triage lui-même.
Le résultat "18 alertes combinées ... 100 % MITRE" cité initialement dans le
README a donc été mesuré sur un jeu partiellement contaminé, où le modèle a
pu apprendre à reproduire une étiquette erronée héritée d'une règle Wazuh
trop permissive plutôt qu'à classifier correctement un comportement malveillant.

`docs/evaluation/labeled_dataset_advanced.json` (hors `legacy/`) a été
nettoyé de ces 7 entrées : il ne contient plus que 11 alertes (1 phishing, 6
PowerShell, 4 C2 beaconing — l'échantillon phishing restant après nettoyage
est trop petit pour tirer une conclusion). **Aucune nouvelle évaluation n'a
été relancée sur ce jeu nettoyé** (nécessite Ollama + la VM, indisponibles
pendant cette passe) : ne citez pas de pourcentage de réussite pour le
scénario phishing avancé tant qu'un nouveau run n'a pas été produit sur le
fichier nettoyé.

## Quels fichiers sont réellement officiels

Voir `docs/evaluation/README.md` (dossier parent) pour la liste des fichiers
qui alimentent effectivement les chiffres cités dans le README principal.
