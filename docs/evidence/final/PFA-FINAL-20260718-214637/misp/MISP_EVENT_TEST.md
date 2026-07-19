# Nouvel événement MISP réel — RUN_ID PFA-FINAL-20260718-214637

## Contexte

MISP `2.5.42`, pile Docker (`misp-core`, `db`, `redis`, `misp-modules`) redémarrée pour cette
phase (arrêtée depuis la gestion RAM séquentielle), reconnectée avec succès
(`GET /servers/getVersion` → `200`).

## Authentification

Connexion réelle en tant que `admin@soc-lab.local` via l'UI, génération d'une clé API dédiée
(`/auth_keys/add`, commentaire `RUN_ID PFA-FINAL-20260718-214637 - test integration reelle`)
pour les appels suivants.

## Événement créé

- **Event ID** : `5`
- **UUID** : `143bd01f-ab9e-4b96-b733-997f80c4e7af`
- **Titre** : `PFA-FINAL-20260718-214637 - C2 beaconing (regle Wazuh 100103), cas TheHive ~40984808`
- **Tag** : `PFA-FINAL-20260718-214637`
- **Distribution** : Your organisation only (pas de partage externe — laboratoire isolé)
- **Attributs** (3, tous réels, liés à la chaîne de preuve existante) :
  1. `domain` (Network activity) : `c2-integration-test.example.invalid` — la même destination
     C2 synthétique `.invalid` utilisée dans le test Cortex et le pipeline réel, `to_ids: true`
  2. `text` (External analysis) : `TheHive case ~40984808` — lien explicite vers le cas réel
     créé par le pipeline (`docs/evidence/.../thehive52/raw/real_pipeline_integration_test_tag_mode.json`)
  3. `text` (Other) : `T1071` — technique MITRE identifiée par le triage Gemma2 réel pour
     l'alerte source

Création via `POST /events/add` (API réelle, réponse complète dans
`raw/event_5_full.json`), pas via l'UI — cohérent avec le pipeline d'intégration réel
(un futur connecteur TheHive→MISP utiliserait la même API).

## Captures d'écran (vérifiées, hashées)

| Fichier | Contenu |
|---|---|
| `screenshots/misp_event5_header.png` | Vue événement #5 : UUID, tag, méta-données, cohérent avec `raw/event_5_full.json` |
| `screenshots/misp_event5_attributes.png` | Liste des 3 attributs, valeurs identiques au JSON brut |

## Sécurité

La clé API MISP générée pour ce test n'a pas été committée en clair dans le dépôt — stockée
uniquement dans `CREDENTIALS.md` local (hors dépôt Git, `soc-lab/CREDENTIALS.md`).

## Ce qui n'a PAS été fait

- Aucune publication de l'événement (`Published: No`) — reste en brouillon, conforme au
  principe de ne pas partager de données de laboratoire au-delà de l'organisation locale.
- Aucun connecteur TheHive→MISP n'a été configuré ou testé dans cette passe (l'événement a
  été créé directement via l'API MISP, pas depuis un cas TheHive).
- Aucun objet MISP (MISP Object) n'a été utilisé, uniquement des attributs simples.

## Preuves brutes

`raw/event_5_full.json` — réponse complète de `GET /events/view/5`, hash dans
`../thehive52/SHA256SUMS_thehive52.csv`.
