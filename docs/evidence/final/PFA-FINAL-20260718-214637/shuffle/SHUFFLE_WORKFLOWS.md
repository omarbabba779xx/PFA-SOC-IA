# Trois nouveaux workflows Shuffle — RUN_ID PFA-FINAL-20260718-214637

## Contexte

Pile Shuffle Docker (`shuffle-opensearch`, `shuffle-backend`, `shuffle-frontend`,
`shuffle-orborus`) redémarrée pour cette phase (arrêtée pour la gestion RAM séquentielle).
Santé confirmée via `GET /api/v1/health` (backend) : création/exécution/suppression de
workflow, datastore et apps tous `true`.

## Authentification

Connexion réelle en tant que `admin@soc-lab.local` via l'UI (`/login`). Les workflows ont été
créés via l'UI (glisser-déposer des triggers), puis lus via l'API interne
(`/api/v1/workflows`, `credentials: 'include'`, réutilisant la session authentifiée du
navigateur) pour produire les preuves brutes.

## Les trois workflows créés

| Nom | ID | Trigger | Objet |
|---|---|---|---|
| `PFA-FINAL-20260718-214637 - Triage niveau 5-7` | `4a25d7c1-b45e-4963-a6bc-1731279dc9d6` | Webhook | Complémentaire au pipeline Wazuh→Gemma→TheHive : gère les alertes de niveau 5-7, sous le seuil d'invocation LLM (`LLM_INVOCATION_THRESHOLD_LEVEL=8`), pour notification/enrichissement manuel |
| `PFA-FINAL-20260718-214637 - Notification TheHive vers Slack (simulation)` | `8a1e2a50-89a6-400a-98a5-b564327f0833` | Webhook | Déclenché à la création d'un cas TheHive, transmet un résumé vers un canal de notification. **Simulation** : aucun vrai webhook Slack externe dans ce laboratoire isolé |
| `PFA-FINAL-20260718-214637 - Enrichissement periodique MISP` | `7a38cc1b-0989-4d05-a507-f58a975789d6` | Schedule | Déclenché périodiquement, interrogerait les événements MISP récents tagués `PFA-FINAL-20260718-214637` pour enrichissement |

Chaque workflow contient un trigger réel (`WEBHOOK` ou `SCHEDULE`, statut `uninitialized` —
non activé, car aucun déclenchement réel n'a été simulé dans cette passe) connecté à un nœud
d'action `Shuffle Tools / repeat_back_to_me` (nœud par défaut "Change Me"), confirmé par
`GET /api/v1/workflows/{id}` — preuve brute complète dans `raw/three_workflows_api.json`.

## Captures d'écran (vérifiées, hashées)

| Fichier | Contenu |
|---|---|
| `screenshots/shuffle_workflows_list.png` | Page "Org Workflows" : les 3 nouveaux workflows visibles à côté de l'ancien workflow de l'itération précédente (non modifié, conservé pour traçabilité) |

## Ce qui n'a PAS été fait

- **Aucun workflow n'a été réellement exécuté** (pas de déclenchement webhook réel, pas
  d'exécution planifiée observée) — seule leur création et leur structure (trigger + action)
  ont été vérifiées.
- Le champ `description` saisi dans l'UI à la création n'a pas persisté côté serveur (vérifié
  via l'API : `description: ""` pour au moins un des workflows) — anomalie honnêtement
  constatée, non corrigée dans cette passe, sans impact sur la validité des 3 workflows
  eux-mêmes (nom, trigger, structure).
- Aucune action métier réelle (appel HTTP vers TheHive/MISP/Slack) n'a été configurée dans
  les nœuds — seul le nœud par défaut `repeat_back_to_me` (Shuffle Tools) est présent.
- Le workflow de l'itération précédente (`SOC PFA - Triage automatise Wazuh...`) n'a pas été
  modifié ni supprimé, conformément à la règle de non-destruction des preuves historiques.

## Preuves brutes

`raw/three_workflows_api.json` — extraction structurée (id, nom, actions, triggers,
branches, timestamps) des 3 workflows via l'API Shuffle, hash dans
`../thehive52/SHA256SUMS_thehive52.csv`.
