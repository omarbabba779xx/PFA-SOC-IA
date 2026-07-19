# Rapport de synthèse — TheHive 5.2.16-1 (Section 17)

**RUN_ID** : `PFA-FINAL-20260718-214637`
**Date du rapport** : 2026-07-19

Rapport requis avant toute reprise des phases Cortex/MISP/Shuffle, conformément au plan
de secours approuvé. Toutes les valeurs ci-dessous sont réelles, relevées directement sur
la VM ou via l'API GitHub — aucune n'est estimée ou fabriquée.

## Cortex

- Version : **3.1.7** (`thehiveproject/cortex:3.1.7`), compatible avec TheHive 5.2.16
  (contrainte : Cortex ≤ 3.2.1).
- État actuel : conteneur `cortex` arrêté (`Exited (137) 21h ago`) — conforme à la
  méthodologie d'exécution séquentielle RAM-consciente (un seul service lourd actif à la
  fois sur les 10 Go de la VM). Sera redémarré pour le test d'intégration Cortex.

## Nouvelle stack TheHive 5.2.16-1 (isolée)

| Champ | Valeur |
|---|---|
| Projet Compose | `pfa-thehive52-final` (`~/pfa-thehive52-final/docker-compose.yml` sur la VM) |
| Image TheHive | `strangebee/thehive@sha256:5ff4b9edd5d6a5bc38c1ef25a38b829527a2944b750b595e7647965097e91bdb` |
| Version TheHive réelle | `5.2.16-1` (confirmée via `GET /api/status` et visible dans l'UI) |
| Volumes | `pfa52-cassandra-data`, `pfa52-elasticsearch-data`, `pfa52-thehive-files` (neufs, aucun lien avec les volumes 5.4.11-1) |
| Réseau | `pfa52-net` (bridge, isolé) |
| Port hôte | `9020` (NAT VirtualBox → VM) |

### État des conteneurs (relevé au moment de ce rapport)

| Conteneur | Statut |
|---|---|
| `pfa52-thehive` | `Up 6 hours` |
| `pfa52-cassandra` | `Up 6 hours (healthy)` |
| `pfa52-elasticsearch` | `Up 6 hours (healthy)` |

### Utilisation RAM (VM, 10 Go alloués)

```
              total        used        free      shared  buff/cache   available
Mem:           9,7Gi       2,6Gi       6,3Gi       0,0Ki       808Mi       6,8Gi
Swap:          7,0Gi       1,3Gi       5,7Gi
```

## Cas TheHive réels créés (preuves complètes dans `raw/`)

| Cas | Compte | Créé via | Objet |
|---|---|---|---|
| `~20640` (#1) | `analyst52@thehive.local` (humain) | UI/API test opérationnel | création, lecture, tag, observable, tâche, recherche |
| `~45280` (#2) | `soc-pipeline52@thehive.local` (service) | API test opérationnel | création, tag `sourceRef:svc-test-001` |
| `~12480` (#3) | `soc-pipeline52@thehive.local` (service) | API test idempotence sourceRef natif | démontre l'absence du champ `sourceRef` (silencieusement ignoré) |
| `~40984808` (#4) | `soc-pipeline52@thehive.local` (service, via pipeline réel) | `create_thehive_case()` réel, mode `tag` | alerte Wazuh réelle → triage Gemma2 réel → cas réel |

- **Observable** créé : `~24736` (cas #1).
- **Tâche** créée : `~40992824` (cas #1).
- **Résultat d'idempotence `sourceRef`** : confirmé réussi en mode `tag`. Deuxième appel
  de `create_thehive_case()` sur la même alerte (`9em5ep8B-jsqxPD_sgRy`) →
  `{"case_id": "~40984808", "created": false}` — **aucun doublon créé**. Preuve brute :
  `raw/real_pipeline_integration_test_tag_mode.json`.

## Captures d'écran

4 captures réelles, prises par l'utilisateur, vérifiées champ par champ contre les preuves
JSON brutes avant acceptation :
- `screenshots/00_organisation_list_version.png`
- `screenshots/01_case_list_real_cases.png`
- `screenshots/02_case_40984808_detail.png`
- `screenshots/03_soclab_users_list.png`

## Hashes SHA-256

Tous les fichiers de preuve de ce dossier sont hashés dans
[`SHA256SUMS_thehive52.csv`](SHA256SUMS_thehive52.csv).

## Commits et CI

| Élément | Valeur |
|---|---|
| Commit (couche de compatibilité + tests) | `e6d6b79` |
| Commit (captures d'écran) | `e3d9ef9` |
| PR | [#3](https://github.com/omarbabba779xx/PFA-SOC-IA/pull/3), mergée `2026-07-19T19:18:30Z` |
| Commit de merge sur `master` | `7ba855d` |
| CI sur le merge (`push` vers `master`) | ✅ **success** (`lint-and-test`, run `29700342808`) |
| Tests locaux | 75/75 passent (`pytest tests/ -v`) |
| Lint | `ruff check scripts/ tests/` — aucune erreur |

## Prochaine étape

Redémarrer Cortex (3.1.7, compatible), effectuer un test réel d'analyseur contre un
observable du cas `~40984808`, documenter le résultat brut avant de passer à MISP puis
Shuffle.
