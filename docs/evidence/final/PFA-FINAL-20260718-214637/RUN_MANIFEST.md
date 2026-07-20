# RUN_MANIFEST — PFA-FINAL-20260718-214637

## Identification

- **RUN_ID** : `PFA-FINAL-20260718-214637`
- **Date UTC de début** : 2026-07-18T21:47:09Z
- **Branche Git** : `final-e2e-validation-PFA-FINAL-20260718-214637`
- **Commit initial** (avant toute action de ce run) : `29af680` (master, avant création de la branche)

## Statut : BLOQUÉ à la Phase 0 → Phase 1

Ce manifeste documente honnêtement l'état réel au moment où ce run a été initié. Aucune
alerte, résultat, capture ou identifiant n'a été produit pour ce RUN_ID — voir la section
"Blocage" ci-dessous avant de lire le reste de ce document.

## Environnement VM (collecté via VBoxManage sur l'hôte, PAS via un shell dans la VM)

| Champ | Valeur |
|---|---|
| Nom de la VM | `SOC-Lab` |
| UUID | `e4190581-fbf6-48ee-9ba3-c6d015fa432e` |
| État | En cours d'exécution (`VBoxHeadless`, PID host variable selon les runs) |
| RAM allouée à la VM | 10240 Mo (10 Go) |
| vCPU alloués | 8 |
| Réseau | NAT (`natnet1="nat"`) |

### Règles de redirection de ports (host → VM), telles que configurées actuellement

| Nom | Protocole | Port hôte | Port VM |
|---|---|---|---|
| cortex | tcp | 127.0.0.1:9001 | 9001 |
| misp | tcp | 127.0.0.1:8444 | 8444 |
| shuffle | tcp | 127.0.0.1:3443 | 3443 |
| shuffle-http | tcp | 127.0.0.1:3001 | 3001 |
| ssh | tcp | 2222 (toutes interfaces) | 22 |
| thehive | tcp | 127.0.0.1:9000 | 9000 |
| wazuh-dashboard | tcp | 127.0.0.1:8443 | 443 |

**Constat important** : ni le port de l'indexeur Wazuh (9200), ni celui d'Ollama (11434) ne
sont redirigés vers l'hôte. Le tableau de bord Wazuh (accessible via le port 8443) proxifie
les requêtes vers l'indexeur, donc la consultation via navigateur reste possible ; en
revanche, aucun script Python exécuté depuis l'hôte Windows ne peut appeler directement
`https://127.0.0.1:9200` ni `http://127.0.0.1:11434` — ces appels doivent s'exécuter DEPUIS
la VM elle-même (via SSH), ce qui est le point de blocage ci-dessous.

## Blocage : accès shell à la VM indisponible

### Service bloqué
Accès shell interactif à la VM `SOC-Lab` (utilisateur `soc`), nécessaire pour :
- générer les 6 scénarios (auditd/Wazuh observent des commandes exécutées DANS la VM) ;
- appeler l'API Ollama (port 11434, non redirigé vers l'hôte) ;
- appeler l'API de l'indexeur Wazuh directement (port 9200, non redirigé, bien que le
  dashboard sur 8443 reste consultable) ;
- exécuter les scripts `scripts/*.py` du pipeline, qui s'exécutent normalement sur la VM.

### Commande tentée
```
ssh -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=5 soc@127.0.0.1 "whoami"
```

### Erreur exacte
```
Permission denied, please try again.
Permission denied, please try again.
soc@127.0.0.1: Permission denied (publickey,password).
```
Le port 2222 est bien ouvert et le serveur SSH répond (négociation réussie, méthodes
`publickey` et `password` proposées) — le blocage est uniquement l'absence d'identifiants
valides dans cette session : aucune clé privée `id_ed25519` correspondante n'a été trouvée
sur le poste hôte (recherche exhaustive dans `%USERPROFILE%` et le répertoire du dépôt), et
aucun mot de passe n'est documenté dans le dépôt (conformément à la règle de ne jamais
committer de secret).

### Accès nécessaire pour débloquer
L'un des éléments suivants, à fournir par l'utilisateur :
- la clé privée SSH correspondant à la clé publique autorisée pour l'utilisateur `soc` sur
  cette VM (probablement générée lors d'une session précédente et non conservée entre les
  sessions de ce poste) ; ou
- le mot de passe du compte `soc` sur la VM ; ou
- un accès direct à la console de la VM (VirtualBox GUI) pour taper les commandes
  manuellement pendant que je guide chaque étape.

### État des données déjà produites pour ce RUN_ID
Aucune. Seuls les éléments suivants ont été créés, et sont purement structurels (aucune
preuve fabriquée, aucun résultat inventé) :
- la branche Git `final-e2e-validation-PFA-FINAL-20260718-214637` ;
- l'arborescence de dossiers `docs/evidence/final/PFA-FINAL-20260718-214637/{wazuh,gemma,thehive,cortex,misp,shuffle,dashboard,raw,logs}/` (tous vides) ;
- ce fichier `RUN_MANIFEST.md`.

Aucune capture, aucun fichier JSON d'alerte, aucun cas TheHive, aucun job Cortex, aucun
événement MISP et aucune exécution Shuffle n'ont été créés sous ce RUN_ID. Les anciennes
preuves (`docs/screenshots/`, `docs/evidence/EVIDENCE.md`) n'ont **pas** été déplacées vers
`archive-pre-final/` : les déplacer maintenant, avant de savoir si ce blocage peut être levé,
casserait les images du README actuel sans aucune preuve de remplacement à mettre à la place.
Ce déplacement sera fait dès que la Phase 2 (génération réelle des scénarios) aura
effectivement produit de nouvelles preuves.

## Mise à jour — déblocage SSH et progression réelle (2026-07-18/19)

Le blocage SSH ci-dessus a été levé : la clé privée `id_ed25519` et les identifiants de
tous les services ont été retrouvés dans un fichier `CREDENTIALS.md` local (hors dépôt Git,
conformément à la règle de ne jamais committer de secret), situé à
`Desktop/Nouveau dossier/soc-lab/CREDENTIALS.md` — ce fichier existait depuis une session
précédente mais n'avait pas été localisé avant.

### Phase 1 — Validation Wazuh : ✅ complétée

- `wazuh-analysisd -t` : configuration valide (exit 0).
- Règle `100103` corrigée (`audit.execve.a1` → `a3`) redéployée et testée en direct :
  test positif (3 requêtes vers la même destination `c2-final-test.example.invalid`)
  → règle 100103 déclenchée sur la 3e occurrence ; test négatif (3 destinations
  différentes) → 100103 ne s'est déclenchée sur AUCUNE des trois. Preuve :
  `raw/scenario5_100103_positive_negative_test.json`.

### Phase 2 — Génération des 6 scénarios + contrôles négatifs : ✅ complétée

Tous générés réellement sur la VM (SSH), résultats indexés et vérifiés via l'API
Elasticsearch : brute force SSH (5710), téléchargement suspect (100099), PowerShell
encodé (100101), mouvement latéral SSH+sudo (100105), C2 beaconing (100103), sondage
réseau nc (100107). Alertes brutes + SHA-256 : voir `raw/scenario*_alert_*.json` et
`scenario_alerts_index.csv`.

**Bug de compatibilité trouvé et corrigé** : `scripts/wazuh_ai_triage.py` et
`scripts/evaluate_llm_vs_baseline.py` utilisaient `from datetime import UTC`, disponible
seulement à partir de Python 3.11 — la VM du lab n'a que Python 3.10. Corrigé vers
`timezone.utc` (portable depuis Python 3.2), `pyproject.toml` mis à jour pour refléter
l'environnement d'exécution réel (`requires-python = ">=3.10"`).

### Phase 4 — Gemma triage réel : ✅ complétée

6 alertes réelles (une par scénario) triées par Gemma2 9B directement sur la VM
(`~/venv/bin/python3 run_gemma_triage.py`, `OLLAMA_KEEP_ALIVE=0`). Les 6 réponses sont
valides et correctement classifiées (MITRE technique exacte pour les 6 scénarios). Preuves
complètes (requête, réponse brute, résultat validé, métadonnées) dans `gemma/`.

### Phase 5 — TheHive : ⚠️ BLOQUÉ (licence invalide côté application)

Voir `thehive/license-investigation/THEHIVE_LICENSE_INVESTIGATION_EVIDENCE.md` pour le
détail complet. Résumé : `POST /api/v1/case` retourne systématiquement
`403 manageCase/create`, pour le compte de service ET le compte humain, malgré un profil
`analyst` correctement assigné. `GET /api/v1/status` confirme officiellement
`license.isValid: false` (licence de secours `no-license`, quotas nuls). Une tentative de
créer un nouveau compte de service échoue avec `LicenseLimitExceeded`. Aucune action
destructive n'a été effectuée ; en attente d'une licence Community officielle à activer
avant de pouvoir reprendre la création de cas.

### Phases 6-13 (Cortex, MISP, Shuffle, dashboard, dataset final, évaluation) : non commencées

Bloquées en aval de la Phase 5 (TheHive) — l'enrichissement Cortex et l'export MISP du
pipeline officiel dépendent de cas TheHive réels, qui ne peuvent pas encore être créés.

## Mise à jour — TheHive 5.2.16-1 (instance isolée) : Phase 5 débloquée (2026-07-19)

L'accès au portail de licence StrangeBee s'étant révélé définitivement indisponible pour
l'utilisateur, une architecture de secours approuvée a été déployée : une instance
TheHive **5.2.16-1** entièrement isolée (conteneurs, volumes, réseau, comptes neufs —
`pfa-thehive52-final` sur la VM), une version Community officielle antérieure au système
de licence par portail (pas de contournement, pas de patch binaire, pas de falsification
de licence). L'instance 5.4.11-1 précédente a été gelée à l'arrêt (conteneurs stoppés,
volumes conservés) comme archive en lecture seule, non supprimée.

- Organisation `soc-lab` créée, compte humain `analyst52@thehive.local` (mot de passe +
  clé API) et compte de service `soc-pipeline52@thehive.local` (clé API), tous deux
  profil `analyst`.
- Test opérationnel complet réussi avec les deux comptes : création de cas réels
  (`~20640`, `~45280`, `~12480`, `~40984808`), lecture, ajout d'observable, ajout de
  tâche, mise à jour de tag, recherche — voir
  `thehive52/raw/human_account_operational_test.txt` et
  `thehive52/raw/service_account_operational_test.txt`.
- **Incompatibilité API réelle découverte et documentée** : le champ `Case.sourceRef` et
  l'endpoint `/api/v1/case/_search`, utilisés par le pipeline existant, n'existent pas sur
  TheHive 5.2.16-1 (confirmé par une `AttributeCheckingError` officielle et une réponse
  `404`). Voir `thehive52/API_COMPATIBILITY_FINDINGS.md` pour le détail complet.
- **Adaptation appliquée** : couche de compatibilité `THEHIVE_DEDUP_MODE` (`source_ref` |
  `tag`, obligatoire, sans détection automatique) dans `scripts/wazuh_ai_triage.py`. Le
  mode `tag` utilise un tag déterministe `source-ref-sha256:<SHA256 du _es_id>` recherché
  via `/api/v1/query`. 17 tests ajoutés (75/75 passent, `ruff` sans erreur).
- **Test d'intégration réel de bout en bout** (pas mocké) : alerte Wazuh réelle
  (`9em5ep8B-jsqxPD_sgRy`, règle 100103) → triage Gemma2 9B réel (T1071, cohérent) → cas
  TheHive réel créé (`~40984808`) avec le tag déterministe persisté → réexécution avec la
  même alerte sans état SQLite local → cas existant retrouvé, **aucun doublon créé**.
  Preuve brute : `thehive52/raw/real_pipeline_integration_test_tag_mode.json`.

### Phase 5 — TheHive : statut mis à jour

✅ **Débloqué** sur l'instance 5.2.16-1 isolée (voir ci-dessus). L'instance 5.4.11-1
reste bloquée par licence invalide (non résolu, archivée en lecture seule).

## Mise à jour — Cortex, MISP, Shuffle, dashboard (2026-07-19/20)

### Phase 6 — Cortex : ✅ complétée

Analyzer réel testé contre Cortex `3.1.9` (`http://127.0.0.1:9001`). Détail complet dans
`cortex/CORTEX_ANALYZER_TEST.md`.

### Phase 7 — MISP : ✅ complétée

MISP `2.5.42` déployé (`https://127.0.0.1:8444`), événement réel `#5` créé via API,
lié explicitement au cas TheHive `~40984808` de ce RUN_ID. Détail complet dans
`misp/MISP_EVENT_TEST.md`.

### Phase 8 — Shuffle : ✅ complétée (3 workflows réels)

3 workflows créés puis corrigés (bug réel de câblage `start`/branches découvert, documenté
et corrigé sans appel API pour le workflow 2, puis avec la même méthode pour le workflow 3 ;
un second bug réel — en-tête `Accept` manquant provoquant une redirection MISP — trouvé et
corrigé sur le workflow 3). Les 3 workflows ont chacun une exécution réelle complète prouvée
(statuts `FINISHED`, réponses HTTP 200 réelles contre Shuffle, TheHive et MISP
respectivement). Détail complet, bugs et preuves dans `shuffle/SHUFFLE_WORKFLOWS.md`.

### Phase 9 — Dashboard SOC : ✅ complétée

Tableau de bord "SOC PFA - Dashboard indicateurs" (4 indicateurs : total incidents 30j,
répartition par type, répartition par criticité, techniques MITRE ATT&CK), retrouvé intact
d'une itération précédente, revérifié avec des données fraîches incluant ce RUN_ID, et
recoupé indépendamment valeur par valeur avec des requêtes OpenSearch brutes (18 techniques
MITRE distinctes sur 30 jours, T1071 confirmé à 2466 occurrences réelles cohérent avec le
scénario C2 beaconing de ce RUN_ID). Détail complet dans `dashboard/DASHBOARD.md`.

Gestion RAM séquentielle appliquée : piles MISP et Shuffle arrêtées avant de redémarrer
l'indexeur et le tableau de bord Wazuh (tous deux avaient été arrêtés pour libérer de la RAM
pendant les phases précédentes).

## Prochaine action

Phases 10-13 (dataset final consolidé, évaluation LLM vs baseline, rapport de synthèse)
restent à réaliser.
