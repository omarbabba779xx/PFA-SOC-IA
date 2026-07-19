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

## Sécurité

Les clés API tierces (AbuseIPDB, VirusTotal) présentes dans la configuration des analyseurs
ont été **redigées** (`[REDACTED-ABUSEIPDB-KEY]`, `[REDACTED-VIRUSTOTAL-KEY]`) dans
`raw/cortex_analyzer_test_raw.txt` avant tout commit — vérifié par une recherche exhaustive
des valeurs brutes avant staging.

## Ce qui n'a PAS été fait

- Aucun test avec un observable `ip`/`hash` réel n'a été effectué dans cette passe (le seul
  test réalisé porte sur le `fqdn` synthétique de l'alerte source).
- L'intégration Cortex↔TheHive 5.2.16-1 via l'interface TheHive (bouton "Run analyzer"
  depuis un cas) n'a pas été configurée ni testée — TheHive a été démarré avec
  `--no-config-cortex` ; ce test a été effectué directement contre l'API Cortex. Le câblage
  UI TheHive→Cortex reste à faire si le pipeline final en a besoin.

## Preuves brutes

`raw/cortex_analyzer_test_raw.txt` (liste des analyseurs avec clés tierces redigées, réponse
de soumission de job, rapport de job complet).
