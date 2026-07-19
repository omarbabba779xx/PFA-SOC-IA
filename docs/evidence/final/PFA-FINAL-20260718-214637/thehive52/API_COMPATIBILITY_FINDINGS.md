# Compatibilité API TheHive 5.2.16-1 vs 5.4.11-1 — constat honnête

**RUN_ID** : `PFA-FINAL-20260718-214637`

## Résumé

Le nouveau déploiement isolé TheHive `5.2.16-1` (compte de service et compte
humain, organisation `soc-lab`) accepte réellement la création de cas —
contrairement à l'instance `5.4.11-1`, qui refusait systématiquement avec
`403 manageCase/create` à cause d'une licence invalide. Trois cas réels ont
été créés avec succès (`~20640`, `~45280`, `~12480`), preuves brutes dans
`raw/human_account_operational_test.txt` et `raw/service_account_operational_test.txt`.

Mais deux incompatibilités API réelles, non fabriquées, ont été découvertes
en testant le pipeline existant (`scripts/wazuh_ai_triage.py`) contre cette
version plus ancienne :

## 1. Le champ `sourceRef` n'existe pas dans le modèle Case de TheHive 5.2.16

`POST /api/v1/case` avec `"sourceRef": "..."` dans le payload est accepté
sans erreur (TheHive 5.2 ignore silencieusement les attributs inconnus à la
création), mais le champ n'est **pas persisté** : absent de la réponse de
création et absent d'un `GET /api/v1/case/{id}` ultérieur.

Confirmé explicitement en interrogeant `/api/v1/query` (endpoint listCase)
avec un filtre sur `sourceRef` : TheHive renvoie une `AttributeCheckingError`
listant tous les attributs réellement disponibles sur `Case` en 5.2.16 —
`sourceRef` n'y figure pas. `sourceRef` a été introduit dans une version de
TheHive postérieure à 5.2.16 (au plus tard 5.4).

## 2. L'endpoint `/api/v1/case/_search` n'existe pas dans TheHive 5.2.16-1

Le pipeline (`find_existing_case_by_source_ref`) appelle
`POST /api/v1/case/_search` avec `{"query":[{"_name":"getCase"},{"_name":"filter","sourceRef":...}]}`.
Sur 5.2.16-1 cet endpoint renvoie `404 NotFoundError`. La recherche de cas en
5.2.16 passe uniquement par `POST /api/v1/query?name=...` avec un pipeline
`listCase` + `filter`, et — comme point 1 le montre — ce filtre ne peut de
toute façon pas porter sur `sourceRef` puisque l'attribut n'existe pas.

## Conséquence pour le mécanisme d'idempotence du pipeline

Le mécanisme actuel (dédoublonnage via recherche `sourceRef` côté TheHive,
en complément de la base SQLite locale) est **incompatible tel quel** avec
TheHive 5.2.16-1. Sans adaptation, `create_thehive_case()` échouerait
systématiquement avec une `TheHiveVerificationError` (fail-closed voulu :
aucune requête HTTP ne réussit sur un endpoint inexistant, donc aucune
alerte ne serait traitée — pas de doublon silencieux, mais blocage total).

## Résolution appliquée : couche de compatibilité `THEHIVE_DEDUP_MODE`

`scripts/wazuh_ai_triage.py` a été adapté avec une couche de compatibilité
explicite, sans détection automatique de version :

- **`THEHIVE_DEDUP_MODE`** (obligatoire, valeurs valides `source_ref` |
  `tag` ; toute autre valeur arrête le script avec `sys.exit(1)` dans
  `validate_configuration()`).
- **Mode `tag`** (utilisé pour ce laboratoire TheHive 5.2.16-1) :
  - `build_source_ref_tag(alert_id)` calcule `source-ref-sha256:<SHA256 hex
    du _es_id>` — longueur stable, aucun caractère spécial, déterministe.
  - `find_existing_case_by_tag(tag)` interroge `/api/v1/query` (le seul
    endpoint de recherche réellement valide sur cette version) avec un
    filtre exact sur `tags`.
  - `create_thehive_case()` n'envoie plus `sourceRef` dans le payload en
    mode `tag` ; le tag déterministe est ajouté aux tags existants, et le
    `_es_id` original reste dans la description pour la traçabilité
    humaine.
  - Fail-closed conservé à l'identique : toute anomalie de recherche (HTTP,
    timeout, réponse qui n'est pas une liste) lève `TheHiveVerificationError`
    plutôt que de supposer l'absence de cas existant.
- **Mode `source_ref`** (comportement d'origine, pour une instance TheHive
  qui supporte réellement le champ) : logique inchangée.
- **En-têtes** : toutes les requêtes TheHive passent désormais par
  `_thehive_headers()`, qui ajoute systématiquement `X-Organisation` (via
  `THEHIVE_ORGANISATION`, défaut `soc-lab`) et `Content-Type: application/json`
  en plus de `Authorization`. Le header `Authorization` n'est jamais
  journalisé (vérifié par un test dédié, voir ci-dessous).

Limite documentée honnêtement : la séquence recherche-puis-création n'est
pas une transaction atomique. Ce pipeline fournit une idempotence
applicative à deux niveaux (SQLite local + recherche déterministe côté
TheHive) **dans un mode d'exécution mono-worker** — ce n'est pas une
garantie "exactly once" distribuée sous exécution parallèle, et le
laboratoire est explicitement contraint à un seul worker actif à la fois.

## Tests ajoutés

17 tests unitaires/intégration ajoutés dans `tests/test_integration_pipeline.py`
(`TestSourceRefTag`, `TestFindExistingCaseByTag`, `TestDedupModeDispatch`,
`TestCreateTheHiveCaseTagMode`, plus un test de bout en bout avec base SQLite
vide simulée dans `TestFullPipelineWithSqliteState`), couvrant : déterminisme
et unicité du tag, format exact `source-ref-sha256:<64 hex>`, identifiant
vide rejeté, forme exacte de la requête `/api/v1/query`, cas trouvé/absent,
timeout/HTTP error/réponse malformée → `TheHiveVerificationError`, dispatch
correct selon `THEHIVE_DEDUP_MODE`, mode invalide rejeté au démarrage,
payload sans `sourceRef` en mode tag, non-duplication lors d'une réutilisation,
en-têtes (`X-Organisation`, `Content-Type`) et absence de la clé API dans les
logs. Suite complète : 75/75 tests passent, `ruff check` sans erreur.

## Test d'intégration réel (pas mocké) — preuve de bout en bout

Exécuté directement sur la VM (`~/venv/bin/python3 ~/real_integration_driver.py`,
copie dans `real_integration_driver.py` de ce dossier), contre l'alerte Wazuh
réelle `9em5ep8B-jsqxPD_sgRy` (règle `100103`, générée par une commande réelle
exécutée sur cette VM juste avant le test — pas fabriquée) et le service
account réel `soc-pipeline52@thehive.local` sur TheHive `5.2.16-1` :

1. Triage LLM réel (Gemma2 9B, Ollama démarré puis arrêté après le test pour
   la RAM) : `T1071` (Command and Control), cohérent avec la règle 100103.
2. Premier appel `create_thehive_case()` : cas réel créé, `~40984808`
   (`created: true`), tag déterministe `source-ref-sha256:d846e4a9...` présent
   dans la réponse.
3. `GET` du cas confirmant la persistance réelle du tag (`sourceRef` absent
   du payload envoyé, comme attendu en mode `tag`).
4. Second appel `create_thehive_case()` avec la **même alerte**, sans état
   SQLite local (simulé par l'absence d'appel à `already_processed()`) :
   `create_thehive_case()` a retrouvé le cas existant via le tag
   (`created: false`, même `case_id`) — **aucun doublon créé**.

Preuve brute complète (stdout, y compris les réponses JSON de Gemma2 et de
TheHive) : `raw/real_pipeline_integration_test_tag_mode.json`. Alerte source :
`raw/source_alert_9em5ep8B-jsqxPD_sgRy.json`.

## Ce qui n'a PAS été fait

- Aucun test de charge multi-worker n'a été exécuté (hors du périmètre
  documenté, voir la limite ci-dessus).
- Le mode `source_ref` n'a pas été re-testé contre TheHive 5.4 dans cette
  passe (déjà couvert par les tests existants et l'investigation
  précédente, qui reste bloquée par la licence — voir
  `docs/evidence/final/PFA-FINAL-20260718-214637/thehive/license-investigation/`).

## Preuves brutes

- `raw/human_account_operational_test.txt` — création cas ~20640, lecture,
  ajout observable ~24736, ajout tâche ~40992824, mise à jour tag, recherche
  par tag (fonctionnelle).
- `raw/service_account_operational_test.txt` — recherche `_search` (404),
  création cas ~45280 (tag-based sourceRef, cas 3), création cas ~12480 avec
  `sourceRef` natif (silencieusement ignoré), `GET` confirmant l'absence du
  champ, `AttributeCheckingError` listant les attributs réels disponibles.
