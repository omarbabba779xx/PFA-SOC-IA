# Test réel d'analyseur Cortex — RUN_ID PFA-FINAL-20260718-214637

## Contexte

Cortex `3.1.7-1` (compatible TheHive 5.2.16, contrainte ≤ 3.2.1), démarré à nouveau sur la
VM (conteneur `cortex`, arrêté depuis la Phase 5 pour la gestion RAM). Son propre backend
Elasticsearch (`thehive-elasticsearch`, conteneur de l'ancienne instance TheHive 5.4 — utilisé
uniquement comme stockage de jobs Cortex, aucune donnée de cas TheHive 5.4 n'a été touchée)
était arrêté et a dû être redémarré pour que Cortex retrouve sa connexion (`NoNodeAvailable`
avant redémarrage, résolu après redémarrage de l'ES et de Cortex).

## Authentification

Connexion réelle en tant que `orgadmin` (organisation `soc-lab`) via `/api/login`, puis
récupération de la clé API existante (`/api/user/orgadmin/key`) pour les appels suivants
(authentification par clé, comme le ferait une intégration TheHive→Cortex réelle).

## Analyseurs disponibles (organisation `soc-lab`)

| Analyseur | Types de données |
|---|---|
| `AbuseIPDB_2_0` | `ip` |
| `FileInfo_8_0` | `file` |
| `VirusTotal_GetReport_3_1` | `file`, `hash`, `domain`, `fqdn`, `ip`, `url` |

## Test exécuté

Observable ajouté au cas réel `~40984808` (créé par le pipeline réel, voir
`thehive52/raw/real_pipeline_integration_test_tag_mode.json`) : `~41005112`, type `fqdn`,
valeur `c2-integration-test.example.invalid` — la destination C2 réelle de l'alerte source
`9em5ep8B-jsqxPD_sgRy` (règle Wazuh 100103), un domaine `.invalid` synthétique conforme à la
règle du laboratoire (jamais de cible publique réelle).

Job soumis via `POST /api/analyzer/{workerId}/run` sur `VirusTotal_GetReport_3_1` :
- Job ID : `EIrse58B1hPvEMuI_x4E`
- Statut final : `Success`
- Durée : ~1 seconde (`startDate` → `endDate`)

## Résultat réel (non fabriqué)

```json
{"summary":{},"full":{"message":"('InvalidArgumentError', 'Domain \"b\\'c2-integration-test.example.invalid\\'\" is not a valid domain pattern')"},"success":true,"artifacts":[],"operations":[]}
```

VirusTotal a lui-même rejeté le domaine `.invalid` comme motif de domaine non valide. C'est
un résultat honnête et attendu : ce domaine est un artefact synthétique du laboratoire,
jamais destiné à interroger un service réel sur une cible publique. Le test démontre malgré
tout le fonctionnement réel de bout en bout de l'intégration Cortex : soumission de job,
exécution par le worker Docker, appel API sortant réel vers VirusTotal, réception et
persistance du résultat, récupération via `GET /api/job/{id}/report`.

## Captures d'écran (vérifiées, hashées)

Prises par l'utilisateur, vérifiées champ par champ contre les preuves brutes ci-dessus.

| Fichier | Contenu |
|---|---|
| `screenshots/cortex_01_job_list.png` | Jobs History Cortex, job `VirusTotal_GetReport_3_1` sur `c2-integration-test[.]example[.]invalid`, statut `Success` |
| `screenshots/cortex_02_job_report_detail.png` | Détail du job, rapport complet identique au JSON brut (`InvalidArgumentError`) |
| `screenshots/03_case_40984808_observable.png` | Onglet Observables du cas `~40984808` dans TheHive, observable `fqdn` (liste, avant le câblage TheHive↔Cortex ci-dessous) |
| `screenshots/04_observable_analyzer_linked.png` | Vue détail de l'observable après le câblage : section "Analyzers" affichant `VirusTotal_GetReport_3_1` avec un ✓ et la date réelle de la dernière analyse (19/07/2026 21:20) |

## Mise à jour — câblage réel de l'intégration TheHive↔Cortex

Contrairement à la section "Ce qui n'a PAS été fait" ci-dessous (rédigée après le premier
test, effectué directement contre l'API Cortex), l'intégration a ensuite été **réellement
câblée et testée avec succès** :

1. Le conteneur `cortex` a été rejoint au réseau Docker de TheHive
   (`docker network connect pfa-thehive52-final_pfa52-net cortex`), lui donnant un nom DNS
   résoluble (`cortex`) depuis le conteneur TheHive.
2. Le service TheHive dans `docker-compose.yml` a été reconfiguré : remplacement de
   `--no-config-cortex` par `--cortex-hostnames cortex --cortex-keys <clé API Cortex>`,
   flags documentés et supportés nativement par l'entrypoint de l'image TheHive
   (confirmé en lisant `/opt/thehive/entrypoint` dans le conteneur).
3. `docker compose up -d thehive` a recréé le conteneur applicatif TheHive (les volumes
   Cassandra/Elasticsearch, donc toutes les données de cas, n'ont pas été touchés — les 4
   cas réels existants sont restés intacts après la recréation, vérifié en se reconnectant).
4. Log TheHive confirmant le chargement : `Add Cortex cortex0: http://cortex:9001`,
   `Loading module org.thp.thehive.connector.cortex.CortexModule`, `Analyzer templates
   already present (found 246)`.
5. **Test réel via l'interface** : ouverture du cas `~40984808` en tant que
   `analyst52@thehive.local`, onglet Observables → menu contextuel → "Run analyzers" →
   `VirusTotal_GetReport_3_1 [cortex0]` apparaît (chargé dynamiquement depuis Cortex, pas
   fabriqué) → sélection et exécution.
6. Job Cortex créé avec les paramètres `{"organisation":"soc-lab","user":"analyst52@thehive.local"}`
   (preuve que c'est bien TheHive, via l'action UI, qui a soumis le job — pas un appel direct
   à l'API Cortex comme le test précédent) : `cortex0/f7oJfJ8Bzlxl2vZwI6aO`.
7. Log TheHive : `Job cortex0/f7oJfJ8Bzlxl2vZwI6aO has finished with status Success, updating
   job ~4136` — le rapport a été importé dans le job TheHive natif `~4136`, récupérable via
   `GET /api/connector/cortex/job/~4136` (même contenu que le rapport Cortex direct :
   `InvalidArgumentError`, domaine `.invalid` rejeté par VirusTotal).
8. Vue "Observable details" dans l'UI TheHive confirme visuellement : section "Analyzers"
   avec `VirusTotal_GetReport_3_1` et un ✓ horodaté — capture `04_observable_analyzer_linked.png`.

Preuves brutes complètes : `raw/thehive_cortex_ui_integration_fix.txt` (commande Compose
modifiée, logs TheHive pertinents, réponse complète du job `~4136`).

## Sécurité

Les clés API tierces (AbuseIPDB, VirusTotal) présentes dans la configuration des analyseurs
ont été **redigées** (`[REDACTED-ABUSEIPDB-KEY]`, `[REDACTED-VIRUSTOTAL-KEY]`) dans
`raw/cortex_analyzer_test_raw.txt` avant tout commit — vérifié par une recherche exhaustive
des valeurs brutes avant staging.

## Ce qui n'a PAS été fait

- Aucun test avec un observable `ip`/`hash` réel n'a été effectué dans cette passe (le seul
  test réalisé porte sur le `fqdn` synthétique de l'alerte source).
- Aucun test de responder (uniquement des analyseurs) n'a été effectué.
- Le câblage TheHive↔Cortex n'a été appliqué qu'à l'instance TheHive 5.2.16-1 isolée, pas à
  l'ancienne instance 5.4.11-1 (toujours bloquée par licence, archivée en lecture seule).

## Preuves brutes

`raw/cortex_analyzer_test_raw.txt` (liste des analyseurs avec clés tierces redigées, réponse
de soumission de job, rapport de job complet).
