# PFA-SOC-IA — SOC Assisté par Intelligence Artificielle

Projet de Fin d'Année, EMSI Tanger, 4IIR — Omar Babba.

> **Ce README a été entièrement repris le 2026-07-19.** Le projet est en cours de
> revalidation complète, run par run, avec un identifiant unique (`RUN_ID`), une chaîne de
> traçabilité explicite (alertes → triage IA → cas TheHive → enrichissement → preuves), des
> captures d'écran systématiquement vérifiées, et des hashes SHA-256 sur chaque fichier de
> preuve. Aucun résultat de l'itération précédente n'est cité ici comme résultat actuel —
> l'ancien README et les anciennes captures sont archivés dans
> [`docs/evidence/archive-pre-final/`](docs/evidence/archive-pre-final/README.md) pour la
> traçabilité, mais ne doivent plus être considérés comme représentatifs de l'état du projet.

## RUN_ID en cours

```
RUN_ID: PFA-FINAL-20260718-214637
Branche : final-e2e-validation-PFA-FINAL-20260718-214637
```

Toutes les preuves de ce run sont dans
[`docs/evidence/final/PFA-FINAL-20260718-214637/`](docs/evidence/final/PFA-FINAL-20260718-214637/RUN_MANIFEST.md),
avec un manifeste (`RUN_MANIFEST.md`) documentant l'état réel de chaque phase, y compris les
blocages.

## Ce qui est réellement validé à ce stade

| Phase | Statut | Preuve |
|---|---|---|
| 1 — Configuration et règles Wazuh | ✅ Validé en direct sur la VM | Règle 100103 corrigée (bug de corrélation par destination) et retestée : positif (3 requêtes vers la même destination → déclenchement) et négatif (3 destinations différentes → aucun déclenchement), voir [`raw/scenario5_100103_positive_negative_test.json`](docs/evidence/final/PFA-FINAL-20260718-214637/raw/scenario5_100103_positive_negative_test.json) |
| 2 — Génération des 6 scénarios + contrôles négatifs | ✅ Réalisé réellement sur la VM | Brute force SSH, téléchargement suspect, PowerShell encodé, mouvement latéral SSH+sudo, C2 beaconing, sondage réseau — alertes réelles indexées, extraites et hashées : [`scenario_alerts_index.csv`](docs/evidence/final/PFA-FINAL-20260718-214637/scenario_alerts_index.csv) |
| 3 — Gel du corpus d'alertes | ✅ | [`raw/full_corpus_window_no80792.json`](docs/evidence/final/PFA-FINAL-20260718-214637/raw/full_corpus_window_no80792.json) |
| 4 — Triage Gemma2 9B | ✅ 6/6 alertes réelles triées, MITRE correct pour chacune | Requête, réponse brute, résultat validé et métadonnées pour chaque scénario dans [`gemma/`](docs/evidence/final/PFA-FINAL-20260718-214637/gemma/) |
| 5 — TheHive (création de cas) | ⚠️ **Bloqué** | Voir section ci-dessous |
| 6-13 — Cortex, MISP, Shuffle, dashboard, dataset final, évaluation | ⏳ Non commencé | Dépendent de la Phase 5 |

## Blocage actuel : licence TheHive invalide

`POST /api/v1/case` retourne systématiquement `403 manageCase/create`, pour le compte de
service **et** le compte humain, malgré un profil `analyst` correctement assigné dans
l'organisation `soc-lab`. L'endpoint officiel `GET /api/v1/status` confirme
`license.isValid: false` (licence de secours `no-license`, quotas nuls pour tous les types
de comptes). Une tentative de créer un nouveau compte échoue avec
`LicenseLimitExceeded`.

Investigation complète, avec 11 captures d'écran vérifiées, réponses API brutes, logs, et
hashes SHA-256 : [`thehive/license-investigation/THEHIVE_LICENSE_INVESTIGATION_EVIDENCE.md`](docs/evidence/final/PFA-FINAL-20260718-214637/thehive/license-investigation/THEHIVE_LICENSE_INVESTIGATION_EVIDENCE.md).

**Aucune action destructive n'a été effectuée** (aucun compte supprimé, aucune migration de
schéma lancée, aucune activation de licence tentée) en attendant une licence TheHive
Community officielle.

## Architecture du laboratoire

- **Wazuh** (Manager + Indexer + Dashboard + `auditd`) — détection, sur VM VirtualBox
  (`SOC-Lab`, Ubuntu 22.04, 8 vCPU / 10 Go RAM).
- **Ollama + Gemma2 9B** (quantifié q4_0) — triage IA local, aucune dépendance cloud.
- **TheHive 5.4.11-1** (`strangebee/thehive:5.4`) + Cassandra + Elasticsearch — gestion des cas.
- **Cortex**, **MISP**, **Shuffle** — enrichissement et orchestration (non encore revalidés
  sous ce RUN_ID).

Contrainte RAM : la VM ne peut pas exécuter toute la pile simultanément. La validation est
séquentielle, service par service, avec libération de RAM entre les phases (Ollama arrêté
avant de démarrer TheHive, etc.).

## Principes de cette validation

- Aucune alerte, résultat, identifiant ou capture n'est fabriqué. Quand un accès manque,
  l'étape correspondante est signalée bloquée avec la commande exacte tentée et l'erreur
  reçue — jamais contournée par une preuve simulée.
- Les simulations offensives (brute force, PowerShell encodé, etc.) sont réalisées dans un
  environnement isolé et contrôlé, avec des domaines `.invalid`, `localhost`, ou le
  sous-réseau privé du laboratoire uniquement.
- Chaque fichier de preuve est accompagné de son hash SHA-256
  ([`SHA256SUMS_ALL.csv`](docs/evidence/final/PFA-FINAL-20260718-214637/SHA256SUMS_ALL.csv)).
- Les captures d'écran sont vérifiées visuellement avant d'être citées comme preuve —
  plusieurs captures de cette validation ont été rejetées et reprises après avoir montré
  par erreur une fenêtre de chat au lieu de l'outil réel.

## Historique

Le projet a été initialement développé et documenté de juillet à mi-juillet 2026 (voir
[`docs/evidence/archive-pre-final/`](docs/evidence/archive-pre-final/README.md) pour cette
version archivée). Une revue externe a ensuite identifié plusieurs limites méthodologiques
(contamination de dataset, doublons dans le jeu de holdout, règles de corrélation buguées,
preuves incomplètes) qui ont motivé la reprise complète documentée dans ce README, avec une
exigence de traçabilité et de vérification live beaucoup plus stricte.

## Structure du dépôt

```
scripts/              Pipeline Python (Wazuh -> Gemma -> TheHive), règles Wazuh, tests
tests/                Tests unitaires et d'intégration (pytest)
docs/evaluation/       Datasets et résultats d'évaluation LLM vs baseline
docs/evidence/final/    Preuves du run en cours, par RUN_ID
docs/evidence/archive-pre-final/   Version archivée pré-reprise (ne pas citer)
docker/                Compose files TheHive, Cortex
```

## Statut des tests et CI

58 tests (unitaires + intégration avec Wazuh/Ollama/TheHive mockés), Ruff, Gitleaks — voir
le workflow GitHub Actions. Ces tests valident le code du pipeline ; ils ne remplacent pas
la validation réelle sur la VM documentée ci-dessus.
