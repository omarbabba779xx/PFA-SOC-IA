# SOC Assisté par Intelligence Artificielle

**Projet de Fin d'Année (PFA) — 4ème année Informatique et Réseaux / Cybersécurité (4IIR)**
**EMSI Tanger — 2025-2026**
**Auteur : Omar Babba**

Conception et déploiement d'une maquette de plateforme SOC (Security Operations Center) assistée par un LLM local, couvrant la détection, le triage assisté par IA, l'enrichissement des observables, la gestion des incidents et l'orchestration automatisée de la réponse.

---

## Sommaire

1. [Contexte et problématique](#contexte-et-problématique)
2. [Architecture](#architecture)
3. [Preuve de bout en bout — cinq scénarios du cahier des charges](#preuve-de-bout-en-bout--cinq-scénarios-du-cahier-des-charges)
4. [Approfondissement — routage automatique par criticité sur un incident unique](#approfondissement--routage-automatique-par-criticité-sur-un-incident-unique)
5. [Parcours expérimental — évaluer le LLM face à une baseline à règles](#parcours-expérimental--évaluer-le-llm-face-à-une-baseline-à-règles)
6. [Détection avancée au niveau commande (auditd)](#détection-avancée-au-niveau-commande-auditd)
7. [Changement de modèle : Mistral 7B → Gemma2 9B](#changement-de-modèle--mistral-7b--gemma2-9b)
8. [Enrichissement et Threat Intelligence (Cortex, MISP)](#enrichissement-et-threat-intelligence-cortex-misp)
9. [Orchestration et réponse automatisée (Shuffle SOAR)](#orchestration-et-réponse-automatisée-shuffle-soar)
10. [Dashboard SOC personnalisé](#dashboard-soc-personnalisé)
11. [Bugs et incidents réels — récapitulatif complet](#bugs-et-incidents-réels--récapitulatif-complet)
12. [Limites d'infrastructure](#limites-dinfrastructure)
13. [Reproduire l'environnement](#reproduire-lenvironnement)
14. [État d'avancement et planning](#état-davancement-et-planning)
15. [Valeur professionnelle](#valeur-professionnelle)

---

## Contexte et problématique

Dans un SOC moderne, les analystes doivent traiter un volume important d'alertes provenant de multiples sources. Le triage manuel devient rapidement lent, répétitif et difficile à maintenir avec un niveau de qualité constant.

Ce projet ne vise pas à remplacer l'analyste ni à construire un SOC de production complet, mais à répondre à une question mesurable :

> **Quelle est la valeur ajoutée d'un LLM local dans le triage des alertes SOC par rapport à une approche classique basée sur des règles de corrélation, en termes de temps de traitement, qualité de classification, mapping MITRE ATT&CK, réduction des faux positifs et aide à la décision ?**

Toute la démarche de ce document suit un principe simple, répété à chaque étape : **mesurer, diagnostiquer les causes d'écart, corriger, re-mesurer** — et documenter honnêtement ce qui fonctionne, ce qui ne fonctionne pas encore, et ce qui a été cassé puis réparé en cours de route.

## Architecture

| Couche | Outil | Rôle |
|---|---|---|
| Détection | Wazuh Agent + Manager (+ `auditd`) | Collecte des logs, détection comportementale et au niveau commande, génération d'alertes |
| Centralisation | Wazuh Indexer + Dashboard | Indexation, recherche, visualisation, métriques SOC |
| Assistant IA | Ollama + **Gemma2 9B instruct (q4_0)** | Résumé, classification, scoring, mapping MITRE ATT&CK |
| Gestion incidents | TheHive 5 | Création de cas, suivi des observables, clôture des incidents |
| Analyse observables | Cortex | Analyse automatique IP/URL/domaines/hash |
| Threat Intelligence | MISP | Partage et enrichissement d'IOC |
| SOAR | Shuffle | Playbook d'enrichissement et de création de cas automatisé |
| Automatisation | Python | Scripts de liaison entre API (Wazuh ↔ Ollama ↔ TheHive) |
| Infrastructure | VirtualBox + Docker Compose | Déploiement reproductible, isolation de la maquette |

### Pipeline SOC

```
Détection (Wazuh + auditd) → Indexation → Triage IA (Ollama/Gemma2 9B) → Évaluation (vs baseline)
        → Création de cas (TheHive) → Enrichissement (Cortex/MISP) → Réponse (Shuffle)
```

**Note sur le choix du modèle** : le projet a démarré avec Mistral 7B, puis est passé à Gemma2 9B après avoir mesuré un gain de précision net et reproductible sur le mapping MITRE (voir [section dédiée](#changement-de-modèle--mistral-7b--gemma2-9b)). Toutes les architectures et tous les scripts actuels utilisent Gemma2 9B par défaut.

## Preuve de bout en bout — cinq scénarios du cahier des charges

Le cahier des charges initial du projet (`PFA_SOC_Assiste_IA_Omar_Babba_2025-2026.pdf`) définit cinq scénarios de test couvrant les cas de base et avancés attendus d'une maquette SOC. Chacun a été rejoué **individuellement, en direct sur la VM**, avec la même exigence de rigueur : preuve par capture réelle à chaque étape de la chaîne (détection Wazuh, triage IA Gemma2 9B, cas TheHive, enrichissement Cortex), plutôt que des captures isolées ou une simple description textuelle.

| Scénario (cahier des charges) | Règle Wazuh | Niveau | Technique MITRE |
|---|---|---|---|
| Brute force SSH | `5710` (sshd, tentative sur utilisateur inexistant) | 5 | T1110 |
| Email de phishing / URL suspecte | `100099` (curl/wget, récupération d'outil externe) | 8 | T1105 |
| Activité PowerShell suspecte | `100101` (exécution PowerShell encodée) | 12 | T1059.001 |
| Mouvement latéral simulé | `100105` (sessions SSH successives + élévation) | 10 | T1021.004 |
| C2 beaconing simulé | `100103` (requêtes réseau répétées) | 10 | T1071 |

### 1. Brute force SSH (T1110)

Six tentatives de connexion SSH vers des utilisateurs inexistants (`bfuser1` à `bfuser6`) déclenchent la règle `5710`, niveau 5 — sous le seuil d'invocation de Gemma (`LLM_INVOCATION_THRESHOLD_LEVEL=8`) et hors de la plage de routage Shuffle (5-7 exclut le niveau 5 dans la configuration actuelle du workflow). Pour documenter malgré tout le chemin Gemma sur ce scénario, l'alerte a été soumise manuellement au triage IA via un script ad hoc (`scripts/triage_single_alert.py`, réutilisant les fonctions de `wazuh_ai_triage.py`) :

![Alerte Wazuh 5710 : tentative SSH sur utilisateur inexistant bfuser6](docs/screenshots/28_wazuh_alert_5710_bruteforce_ssh.png)

![Cas TheHive #2168 généré par Gemma2 9B, tags wazuh/triage-ia/T1110](docs/screenshots/37_thehive_case_bruteforce.png)

Cortex analyse l'adresse source (`127.0.0.1`, la VM elle-même dans ce scénario de laboratoire) via `AbuseIPDB_2_0` :

![Analyse Cortex AbuseIPDB sur 127.0.0.1](docs/screenshots/38_cortex_analysis_bruteforce.png)

### 2. Phishing / récupération d'outil externe (T1105)

Un `curl` vers un domaine simulé (`phishing-simulated-payload.example.invalid/malicious.sh`) déclenche la règle `100099`, niveau 8 — au-dessus du seuil Gemma, traité automatiquement par `wazuh_ai_triage.py` :

![Alerte Wazuh 100099 : curl vers un domaine de phishing simulé](docs/screenshots/32_wazuh_alert_100099_phishing.png)

![Cas TheHive #2144 généré par Gemma2 9B, tags wazuh/triage-ia/T1105](docs/screenshots/33_thehive_case_phishing.png)

Cortex analyse le domaine cible via `VirusTotal_GetReport_3_1` : l'analyseur rejette explicitement le domaine (`InvalidArgumentError`, motif de domaine non valide) car le TLD `.invalid` utilisé pour ce scénario simulé n'est volontairement pas un domaine réel enregistrable — comportement attendu et documenté ici tel quel plutôt que masqué :

![Analyse Cortex VirusTotal sur le domaine de phishing (rejet attendu, TLD .invalid)](docs/screenshots/39_cortex_analysis_phishing.png)

### 3. Activité PowerShell suspecte (T1059.001)

Une commande `pwsh -enc <base64>` (téléchargement distant encodé) déclenche la règle `100101`, niveau 12 (critique) :

![Alerte Wazuh 100101 : commande PowerShell encodée capturée dans data.audit.execve](docs/screenshots/29_wazuh_alert_100101_powershell.png)

![Cas TheHive #2151 généré par Gemma2 9B, tags wazuh/triage-ia/T1059.001](docs/screenshots/34_thehive_case_powershell.png)

Ce scénario n'a pas d'observable réseau exploitable par Cortex (l'exécution est purement locale à l'endpoint, sans IP ni domaine de destination réel dans le payload encodé de démonstration) : étape volontairement absente ici plutôt que simulée artificiellement.

### 4. Mouvement latéral simulé (T1021.004)

Deux connexions SSH successives vers la machine elle-même suivies d'une élévation `sudo` déclenchent la règle `100105`, niveau 10 :

![Alerte Wazuh 100105 : sessions SSH successives avec élévation, previous_output visible](docs/screenshots/30_wazuh_alert_100105_lateral_movement.png)

![Cas TheHive #2150 généré par Gemma2 9B, tags wazuh/triage-ia/T1021.004](docs/screenshots/35_thehive_case_lateral_movement.png)

Cortex analyse l'adresse source des connexions (`10.0.2.2`, passerelle réseau host-only VirtualBox) via `AbuseIPDB_2_0` :

![Analyse Cortex AbuseIPDB sur 10.0.2.2](docs/screenshots/40_cortex_analysis_lateral_movement.png)

### 5. C2 beaconing simulé (T1071)

Cinq requêtes `curl` avec jitter (délai aléatoire 5-12 s) vers un domaine simulé déclenchent la règle `100103`, niveau 10 (corrélation de requêtes répétées) :

![Alerte Wazuh 100103 : requête curl vers un domaine de C2 simulé](docs/screenshots/31_wazuh_alert_100103_c2_beaconing.png)

![Cas TheHive #2145 généré par Gemma2 9B, tags wazuh/triage-ia/T1071](docs/screenshots/36_thehive_case_c2_beaconing.png)

Cortex analyse le domaine de destination via `VirusTotal_GetReport_3_1` — même comportement de rejet explicite que pour le scénario phishing, et pour la même raison (TLD `.invalid`) :

![Analyse Cortex VirusTotal sur le domaine C2 (rejet attendu, TLD .invalid)](docs/screenshots/41_cortex_analysis_c2_beaconing.png)

### Bilan

Les cinq scénarios du cahier des charges sont ainsi tous rejoués et documentés individuellement, chacun tracé de la détection Wazuh jusqu'au triage IA Gemma2 9B et au cas TheHive correspondant (tags `wazuh`/`triage-ia`/technique MITRE), avec enrichissement Cortex sur les quatre scénarios disposant d'un observable réseau exploitable. Le scénario de brute force, en dessous du seuil normal d'invocation de Gemma, a nécessité un script de triage ciblé (`scripts/triage_single_alert.py`) pour prouver que le chemin IA fonctionne aussi sur ce type d'alerte, en complément du chemin Shuffle qui le couvre normalement en production.

**Bug rencontré en préparant cette preuve** : la VM s'est retrouvée en situation de mémoire quasi épuisée (111 Mo libres, swap à 100 %) après plusieurs cycles de triage Gemma successifs sans redémarrage intermédiaire des autres services, provoquant un blocage de l'interface Cortex (jobs restant indéfiniment à l'état `Waiting`, page web ne répondant plus). Diagnostiqué via `free -h` sur la VM. Corrigé en deux temps : déchargement explicite du modèle Gemma d'Ollama (`keep_alive:0` sur l'API `/api/generate`) pour libérer ~4,5 Go, puis redémarrage du conteneur Cortex pour débloquer sa file de jobs bloqués — les deux jobs en attente se sont immédiatement terminés avec succès après le redémarrage.

## Approfondissement — routage automatique par criticité sur un incident unique

Au-delà des cinq scénarios rejoués séparément, les deux chemins d'automatisation du projet (Shuffle pour le routage instantané, `wazuh_ai_triage.py`/Gemma pour le triage qualitatif) ont aussi été rejoués **sur un seul et même incident simulé**, pour éliminer tout doute sur leur cohérence quand ils cohabitent : une source unique (`1.1.1.1`) déclenche d'abord une action de reconnaissance (sondage de port via `nc`, règle `100107`, niveau 6 → chemin Shuffle), puis une récupération d'outil externe (`curl`, règle `100099`, niveau 8 → chemin Gemma). Le seuil d'invocation du LLM (`LLM_INVOCATION_THRESHOLD_LEVEL=8`) et la condition Shuffle (`rule.level` entre 5 et 7) sont donc bien complémentaires et non redondants sur ce cas concret.

Les deux alertes générées par ce scénario, visibles côte à côte dans Wazuh avec le même timestamp (`16:56:55`) :

![Alertes Wazuh niveau 6 (reconnaissance) et niveau 8 (récupération d'outil) sur la même cible](docs/screenshots/21_wazuh_events_1_1_1_1_incident.png)

Détail de l'alerte de reconnaissance (règle `100107`) : les champs `audit.execve` bruts montrent explicitement la commande exécutée (`nc -z -w2 1.1.1.1 80`), preuve que l'IP cible est bien celle du scénario :

![Détail de l'alerte 100107 avec l'IP cible visible dans audit.execve](docs/screenshots/22_wazuh_alert_100107_detail_1_1_1_1.png)

Le workflow Shuffle traite cette alerte de niveau 6 **automatiquement, sans intervention manuelle** — capture de l'historique d'exécution en direct (`Status: FINISHED`, exécutions successives visibles toutes les 1-2 secondes sous l'effet du flux d'alertes réel de la VM) :

![Historique d'exécution en direct du workflow Shuffle](docs/screenshots/23_shuffle_workflow_execution_live.png)

Le cas TheHive résultant, créé automatiquement par `SOC Automation` (compte de service Shuffle) quelques secondes après l'alerte, avec les tags `soc-lab`, `shuffle-auto`, `routine`, `wazuh` et une description qui référence explicitement le webhook Shuffle et l'enrichissement Cortex :

![Cas TheHive routine créé automatiquement par Shuffle](docs/screenshots/24_thehive_routine_case_shuffle_live.png)

**Cortex analyse le même indicateur, sur le même cas** : l'IP `1.1.1.1` a été ajoutée comme observable au cas TheHive `#1344` (celui créé par Shuffle ci-dessus), avec une description renvoyant explicitement au cas et aux deux règles Wazuh (`100107`, `100099`). Une analyse `AbuseIPDB_2_0` a ensuite été lancée sur cet indicateur :

![Rapport d'analyse Cortex AbuseIPDB sur l'IP 1.1.1.1 du cas #1344](docs/screenshots/25_cortex_analysis_1_1_1_1.png)

**MISP capitalise le verdict, toujours sur le même incident** : un événement MISP a été créé en référençant explicitement le numéro de cas TheHive (`#1344`), les deux règles Wazuh à l'origine de l'alerte, et le verdict Cortex complet (score `0/100`, indicateur *whitelisted*, usage *Content Delivery Network*, 37 rapports) dans le commentaire de l'attribut `ip-src` :

![Événement MISP référençant le cas #1344 et le verdict Cortex](docs/screenshots/26_misp_event_1_1_1_1.png)

Avec ces captures, les **cinq premiers outils de la chaîne** (Wazuh, Shuffle, TheHive, Cortex, MISP) tracent le **même incident unique**, du premier signal de reconnaissance jusqu'à la capitalisation de threat intelligence — pas cinq démonstrations juxtaposées après coup. Le sixième outil, Gemma2 9B, est documenté séparément ci-dessous sur le chemin de criticité qui lui est propre.

**Sur le chemin Gemma (niveau ≥ 8) pour cet incident précis** : le script `wazuh_ai_triage.py` a bien détecté et récupéré l'alerte `100099` (niveau 8) associée au même incident via la requête serveur filtrée (voir bug corrigé ci-dessous), confirmant que le routage par seuil fonctionne correctement en amont. Faire aboutir réellement l'inférence Gemma2 9B jusqu'à un cas TheHive a nécessité d'identifier et corriger trois bugs distincts, au fil de tentatives dans des conditions de charge croissantes :

- **Premières tentatives** (stack complète active, 6 outils simultanés) : `llama-server` systématiquement tué par le noyau (`OOM killed`, confirmé via `dmesg`) après plusieurs minutes, RAM et swap saturés. Contournement temporaire : arrêt de Cortex/MISP puis de toute la stack Shuffle pour libérer de la RAM — insuffisant seul (une tentative dans ces conditions a tourné 21 minutes sans OOM mais sans jamais aboutir, `ps` montrant un temps CPU cumulé croissant en continu).
- **Bug n°1 — génération de tokens non bornée** : l'appel `/api/generate` d'Ollama dans `wazuh_ai_triage.py` ne fixait aucune limite `num_predict`. En mode `format: "json"`, le modèle continuait à générer indéfiniment au lieu de s'arrêter après une courte classification, ce qui expliquait à la fois les temps de calcul démesurés et une partie de la pression mémoire. Corrigé en ajoutant `"num_predict": 300` aux options de génération.
- **Bug n°2 — sous-allocation vCPU** : la VM ne disposait que de 4 vCPU alors que l'hôte (AMD Ryzen 7 5700X, 8 cœurs/16 threads) n'était chargé qu'à ~9 %. Corrigé par `VBoxManage modifyvm "SOC-Lab" --cpus 8` (VM arrêtée puis redémarrée), portant l'utilisation CPU observée à 500-680 % pendant l'inférence.
- **Bug n°3 — résolution DNS locale erronée côté client HTTP** : une fois les deux bugs précédents corrigés, la classification LLM aboutissait en quelques minutes, mais la création du cas TheHive échouait systématiquement avec `401 Unauthorized`, alors qu'un `curl` manuel avec la même clé API réussissait à chaque fois (`201 Created`). Isolé par comparaison directe : la bibliothèque Python `requests` résout `localhost` en IPv6 (`::1`) sur cette VM, connexion sur laquelle l'authentification par clé API de TheHive échoue silencieusement, alors que `curl` privilégie IPv4 et réussit. Corrigé en remplaçant `http://localhost:9000` par `http://127.0.0.1:9000` dans `THEHIVE_URL`.

Avec les trois correctifs déployés, une exécution complète du script a traité 5 alertes réelles (niveau ≥ 8) et créé 5 cas TheHive sans aucune erreur 401, dont un directement rattaché à l'alerte `100099` de ce même incident (`1.1.1.1`, technique `T1105`) :

![Cas TheHive #2134 créé automatiquement par l'analyse Gemma2 9B, tags wazuh/triage-ia/T1105](docs/screenshots/27_thehive_gemma_triage_1_1_1_1.png)

Le cas porte les tags `wazuh`, `triage-ia`, `T1105`, une sévérité `MEDIUM` assignée par le triage hybride, et une description générée par le LLM reprenant la tactique/technique MITRE ainsi qu'une recommandation d'investigation — la preuve que les **six outils** de la chaîne (Wazuh, Shuffle, TheHive, Cortex, MISP, Gemma2 9B) tracent bien le même processus de bout en bout, chacun sur son propre chemin de criticité.

### Bugs supplémentaires trouvés et corrigés en préparant cette preuve

1. **Volume de bruit `auditd` extrême** (jusqu'à ~14 000 alertes/15 min) : la règle `auditd` de base auditait tous les processus, y compris les appels internes de Docker (`runc`, `containerd`, `coreutils`) déclenchés en continu par les conteneurs eux-mêmes. Diagnostiqué via une agrégation `_count` sur `rule.description` dans l'indexeur. Corrigé en restreignant la règle aux sessions utilisateur réelles : `-F auid>=1000 -F auid!=4294967295`, réduisant le bruit d'un facteur ~10.
2. **Bug de filtrage côté client dans `fetch_recent_alerts()`** : la fonction récupérait les *N* alertes les plus récentes puis filtrait par `rule.level` en mémoire — sur une VM à fort volume de bruit résiduel, les alertes significatives mais peu fréquentes sortaient de la fenêtre avant même d'atteindre le filtre. Corrigé en déplaçant le filtre `rule.level` directement dans la requête Elasticsearch/OpenSearch (`bool.filter` côté serveur), vérifié en conditions réelles (`27 alerte(s) recuperee(s)` contre `0` auparavant sur le même jeu de données).
3. **Disque VM saturé à 100 %, arrêtant silencieusement `auditd` pendant plus de 12 heures** : aucune nouvelle alerte de sécurité n'était générée sans qu'aucune erreur ne remonte explicitement dans les tableaux de bord habituels. Diagnostiqué en comparant l'horodatage courant à celui de la dernière ligne du fichier `/var/log/audit/audit.log` brut. Corrigé en trois temps : nettoyage Docker (conteneurs arrêtés et images inutilisées), purge des journaux systemd de plus de 24h, puis agrandissement définitif du disque virtuel VirtualBox (`VBoxManage modifymedium disk --resize`, 59 → 80 Go), suivi de l'extension de la table GPT, de la partition (`growpart`) et du système de fichiers (`resize2fs`).
4. **Corruption de commit logs Cassandra** (backend de TheHive) après plusieurs arrêts brutaux de VM survenus pendant la session : `CommitLogReadHandler$CommitLogReadException` empêchait Cassandra de démarrer. Les commits logs corrompus ont été identifiés et mis en quarantaine (déplacés, pas supprimés) ; les données déjà persistées en SSTable (cas TheHive existants) n'ont pas été affectées.
5. **Corruption de shards sur l'indexeur Wazuh** (même cause racine — arrêts brutaux répétés) : `CorruptIndexException: codec footer mismatch` sur 2 des 3 shards primaires de l'index du jour, cluster passé en état `RED`, bloquant toute nouvelle ingestion (Filebeat en échec `temporary bulk send failure` en boucle). Sans réplica configuré sur ce cluster à un seul nœud, ces shards n'étaient pas récupérables : l'index corrompu du jour a été supprimé (perte de quelques centaines d'alertes de bruit déjà indexées, aucune donnée de valeur), débloquant immédiatement l'ingestion (cluster repassé `GREEN`, nouvelles alertes indexées en quelques secondes).
6. **Intégration Shuffle disparue de `ossec.conf` après un redémarrage de VM** (bug déjà rencontré et documenté plus haut, réapparu identiquement) — ré-ajoutée, avec une vigilance supplémentaire : le premier correctif appliqué avait par erreur dupliqué le bloc `<integration>` dans les deux sections `<ossec_config>` du fichier (ce fichier Wazuh en contient légitimement deux) ; corrigé en ne conservant l'intégration que dans la section principale.
7. **Image Docker de l'analyseur Cortex `AbuseIPDB` introuvable** (`Image not found: ghcr.io/thehive-project/abuseipdb:2`) lors de la première tentative d'analyse sur `1.1.1.1`, alors qu'une analyse identique avait réussi 9 jours plus tôt sur un autre indicateur : effet de bord probable d'un des nettoyages Docker effectués plus tôt dans la session (`docker image prune`). Corrigé par un simple `docker pull` de l'image manquante, analyse relancée avec succès dans la foulée.

## Parcours expérimental — évaluer le LLM face à une baseline à règles

Un jeu de **38 alertes labellisées manuellement** a été constitué à partir de 9 scénarios (brute force SSH, connexions valides, sudo/su, création/suppression de compte, tâche planifiée, commande obfusquée). Chaque alerte a été classifiée par deux méthodes indépendantes et comparée à une référence manuelle :
- **Baseline à règles** : mapping natif de Wazuh (`rule.level` → criticité, `rule.mitre` → tactique/technique), sans LLM.
- **LLM** : via Ollama, avec un prompt structuré demandant une sortie JSON stricte.

### Trois itérations jusqu'à une mesure fiable

| Itération | Ce qui a été corrigé | Correspondance MITRE (LLM) | Écart de criticité (LLM) |
|---|---|---|---|
| 1 — prompt initial | — | 2.6 % | 1.55 |
| 2 — sortie JSON forcée, vocabulaire de criticité normalisé | Format de sortie non contraint, dérive de langue | 13.2 % | 0.71 |
| 3 — référence *par alerte* (pas par bloc de scénario) + exemples few-shot | Référence de test trop grossière | **100 %** | 0.50 |

À chaque itération, la baseline restait stable (28.9 % → 73.7 % de correspondance MITRE selon la granularité de la référence, écart de criticité 0.13-0.76). **Conclusion** : une bonne partie de ce qui ressemblait à une "limite de l'IA" en itération 1 était en réalité une limite de l'expérimentation (prompt, données de référence) — à vérifier avant toute conclusion hâtive sur les capacités du modèle.

Résultats bruts : [`docs/evaluation/evaluation_results.json`](docs/evaluation/evaluation_results.json), [`evaluation_results_v2.json`](docs/evaluation/evaluation_results_v2.json), [`evaluation_results_v3.json`](docs/evaluation/evaluation_results_v3.json).

### Renforcement méthodologique

Quatre limites réelles ont été identifiées et corrigées après une relecture critique des premiers résultats :

**1. Jeu de test holdout (généralisation, pas mémorisation)** — un second jeu de 36 alertes issues de 6 scénarios *jamais utilisés pour construire le prompt* a été testé :

| Métrique | Baseline | LLM |
|---|---|---|
| Correspondance MITRE | 61.1 % | **94.4 %** |
| Écart de criticité | 0.11 | 0.75 |

Sur ce jeu jamais vu, la baseline perd en précision (61.1 % contre 73.7 %) alors que le LLM reste stable (94.4 % contre 97.4 %) — un argument de généralisation en faveur du LLM, pas contre.

**2. Approche hybride** — `wazuh_ai_triage.py` combine désormais les deux méthodes selon leurs forces : **criticité finale = baseline** (déterministe, fiable), **mapping MITRE + résumé = LLM** (~97 % de correspondance). Le LLM n'est plus jugé sur la tâche où il est faible.

**3. Triage à deux niveaux** — le LLM (~40-120 s/alerte selon le modèle) n'est invoqué qu'après filtrage par la baseline (`LLM_INVOCATION_THRESHOLD_LEVEL`), jamais sur le bruit de faible niveau. Vérifié en exécution réelle : `17 alerte(s) filtrée(s) par la baseline (bruit), 3 soumises au LLM`.

**4. Variance mesurée sur 3 répétitions** (même jeu, température LLM = 0.1) :

| Répétition | Correspondance MITRE | Écart de criticité |
|---|---|---|
| 1 | 100.0 % | 0.58 |
| 2 | 94.7 % | 0.58 |
| 3 | 97.4 % | 0.63 |
| **Moyenne ± écart-type** | **97.4 % ± 2.2 %** | **0.60 ± 0.02** |

La baseline, déterministe, reste strictement constante (73.7 % / 0.13) sur les 3 répétitions.

Résultats bruts : [`evaluation_results_holdout.json`](docs/evaluation/evaluation_results_holdout.json), [`evaluation_results_rep1.json`](docs/evaluation/evaluation_results_rep1.json) à `rep3.json`.

## Détection avancée au niveau commande (auditd)

Quatre scénarios avancés (PowerShell suspect, mouvement latéral, C2 beaconing, phishing/dropper) nécessitent une capacité que le ruleset Wazuh natif n'a pas : l'inspection des **commandes exécutées**. Mise en place :

1. `auditd` installé avec la règle officielle Wazuh (`auditctl -a always,exit -F arch=b64 -S execve -k audit-wazuh-c`, clé `audit-wazuh-c` de la CDB list officielle).
2. Règles personnalisées héritant de la règle native `80792` (*Audit: Command*) :

| ID règle | Détection | Technique MITRE | Mécanisme |
|---|---|---|---|
| `100099` | Exécution de `curl`/`wget` (récupération de payload) | T1105 | hérite de `80792` + `audit.command` |
| `100101` | Exécution de `pwsh`/`powershell` | T1059.001 | hérite de `80792` + `audit.command` |
| `100103` | `curl`/`wget` répétés (≥3 en 90s, jitter) | T1071 | corrélation par fréquence sur `100099` |
| `100105` | Connexions SSH répétées + élévation sudo (≥3 en 120s) | T1021.004 | corrélation par fréquence sur `5715` |
| `100107` | Exécution de `nc`/`ncat` (sondage de port) | T1046 | hérite de `80792` + `audit.command` |

### Quatre bugs réels trouvés et corrigés

1. **Décodeur `auditd` attend des enregistrements pré-fusionnés** (`SYSCALL`+`EXECVE`+`CWD`+`PATH`+`PROCTITLE` sur une seule ligne, ce que le fichier brut ne produit jamais) → écrit [`scripts/audit_merge.py`](scripts/audit_merge.py), un service qui fusionne les enregistrements avant qu'ils n'atteignent Wazuh.
2. **Troncature de `full_log` à 400-500 caractères** coupait le contenu `EXECVE` désormais plus loin dans la ligne fusionnée → portée à 900 caractères.
3. **Caractères de contrôle non imprimables** (`\x1d` inséré par `auditd`) cassaient les requêtes JSON vers le LLM → nettoyage par regex avant envoi.
4. **OOM systématique à la 3ᵉ requête** (accumulation du cache de prompt Ollama) → arrêt temporaire de TheHive/Cassandra/Elasticsearch pendant l'évaluation.

**Premier résultat, honnête** : après correction des 4 bugs, le LLM (Mistral 7B) obtenait **0,0 %** de correspondance MITRE sur ces 4 scénarios — un vrai écart de généralisation (hors distribution few-shot), pas un artefact de bug. Diagnostiqué comme : les 9 scénarios d'origine faisaient partie des exemples few-shot du prompt, ces 4 nouveaux n'en faisaient jamais partie.

**Corrections apportées** :
- Ajout de 4 exemples few-shot ciblés → 0,0 % → 66,7 % immédiatement (PowerShell et C2 beaconing à 100 % chacun).
- Un biais caché découvert : la description de la règle `100099` contenait le mot "phishing", biaisant systématiquement le LLM vers le mauvais code → reformulée, exemple few-shot renforcé.
- Tentative `temperature=0.0` pour réduire la variance restante sur le phishing → **a empiré le résultat** (16,7 % contre 40 % à `temperature=0.1`), contre-intuitif mais reproductible → réglage `0.1` conservé.

**Bilan avec Mistral 7B** : 3 scénarios sur 4 fiables à 100 % (PowerShell, C2 beaconing, mouvement latéral). Le 4ᵉ (phishing/T1105) restait variable (17-40 %) — la limite qui a motivé le changement de modèle ci-dessous.

Incident de sécurité découvert pendant cette implémentation : l'audit des commandes a capturé **en clair** nos propres appels `curl -u admin:MOTDEPASSE` dans l'index Wazuh. Remédiation : documents purgés, mot de passe régénéré, toutes les authentifications `curl` utilisent désormais `~/.netrc`.

## Changement de modèle : Mistral 7B → Gemma2 9B

Face à la limite persistante de Mistral 7B sur le scénario phishing, le modèle a été remplacé par **Gemma2 9B instruct (q4_0)**, sans aucun autre changement (même prompt, mêmes exemples few-shot, même `temperature=0.1`).

| Jeu de test | Mistral 7B | Gemma2 9B |
|---|---|---|
| Phishing, lot 1 (6 alertes) | 16,7 % (1/6) | **100 % (6/6)** |
| Phishing, lot 2 (5 alertes) | 40 % (2/5) | **100 % (5/5)** |
| Phishing, lot 3 — reproductibilité (4 alertes) | — | **100 % (4/4)** |
| 18 alertes combinées (phishing + PowerShell + C2) | 66,7 % | **100 % (18/18)**, écart de criticité 0,00 |

**Cumulé sur les 3 lots phishing testés avec Gemma2 9B : 15/15 (100 %)** — un résultat reproductible sur trois batches indépendants, pas un coup de chance sur un seul run. Résultats bruts : [`evaluation_results_phishing_gemma.json`](docs/evaluation/evaluation_results_phishing_gemma.json), [`..._gemma2.json`](docs/evaluation/evaluation_results_phishing_gemma2.json), [`..._repro.json`](docs/evaluation/evaluation_results_phishing_repro.json), [`evaluation_results_advanced_gemma.json`](docs/evaluation/evaluation_results_advanced_gemma.json).

**Précision honnête** : sur le lot de reproductibilité, l'écart moyen de criticité du LLM était de 1,00 (le modèle a répondu "haute" au lieu de "moyenne"). Sans impact réel : l'architecture hybride utilise la criticité de la baseline à règles, jamais celle du LLM, pour la création des cas TheHive.

**Contrepartie mesurée, pas dissimulée** : Gemma2 9B est environ **2 fois plus lent** (~119 s/alerte contre ~60 s pour Mistral) et pèse davantage en RAM (5,4 Go contre 4,1 Go sur disque). Faire tourner Gemma2 en continu en plus de toute la stack a de nouveau provoqué une surcharge sévère de la VM (`load average` 26+, RAM quasi saturée) — la même limite d'infrastructure déjà documentée, plus marquée avec un modèle plus gros.

**Décision retenue** : `OLLAMA_MODEL=gemma2:9b-instruct-q4_0` est le réglage par défaut dans les deux scripts consommateurs ([`evaluate_llm_vs_baseline.py`](scripts/evaluate_llm_vs_baseline.py), [`wazuh_ai_triage.py`](scripts/wazuh_ai_triage.py)), avec le compromis de latence explicitement documenté.

## Enrichissement et Threat Intelligence (Cortex, MISP)

### Cortex

Déployé en réutilisant l'Elasticsearch déjà provisionné pour TheHive (économie de RAM). Analyseurs activés et testés avec des résultats réels :

| Analyseur | Couvre | Résultat de test |
|---|---|---|
| `FileInfo_8_0` | Fichiers (PE, PDF, OLE) | Extraction de métadonnées fonctionnelle (local, aucune clé requise) |
| `AbuseIPDB_2_0` | IP | IP `8.8.8.8` → score d'abus 0/100, "Content Delivery Network", 28 signalements ; réutilisé en direct sur les IP réelles des scénarios (`127.0.0.1`, `1.1.1.1`, `10.0.2.2`) |
| `VirusTotal_GetReport_3_1` | Fichier, hash, domaine, IP, URL | Hash EICAR → 66/74 moteurs antivirus le détectent ; réutilisé sur les domaines simulés des scénarios phishing/C2 |

**Lien TheHive ↔ Cortex** : configuré nativement (Platform Management > Connectors), test de connexion réussi. Voir les captures dans les sections [Preuve de bout en bout](#preuve-de-bout-en-bout--cinq-scénarios-du-cahier-des-charges) et [Approfondissement](#approfondissement--routage-automatique-par-criticité-sur-un-incident-unique).

### MISP

Déployé via [misp-docker](https://github.com/MISP/misp-docker) officiel, sur le port `8444` (le 443 étant occupé par le dashboard Wazuh). Contrainte RAM résolue en réduisant `INNODB_BUFFER_POOL_SIZE`/`PHP_MEMORY_LIMIT` par défaut.

**Lien TheHive ↔ MISP** : configuré nativement, test de connexion réussi. Voir la capture de l'événement MISP dans la section [Approfondissement](#approfondissement--routage-automatique-par-criticité-sur-un-incident-unique).

## Orchestration et réponse automatisée (Shuffle SOAR)

Déployé depuis les sources officielles (frontend, backend, orborus, OpenSearch), Orborus en mode conteneurs simples (`SHUFFLE_SWARM_CONFIG=noswarm`) pour éviter des échecs de résolution DNS internes reproductibles en mode Swarm sur ce lab single-node.

**Playbook réel à 3 étapes** :

```
Webhook (reçoit alerte Wazuh) → Enrichissement Cortex (GET /api/status)
        → SI rule.level > 7  → création cas TheHive "ESCALADE" (sévérité Haute)
        → SI rule.level 5-6  → création cas TheHive "routine" (sévérité Basse)
        → SI rule.level <= 4 → aucun cas créé (bruit filtré)
```

**Connexion réelle à Wazuh** : bloc d'intégration natif `<integration><name>shuffle>` ajouté à `ossec.conf`, chaque alerte Wazuh réelle est transmise automatiquement au workflow.

### Bugs réels rencontrés et corrigés (par ordre de découverte)

1. **Nœud fantôme** ("Change Me" jamais reconfiguré malgré une UI trompeuse) → corrigé en réécrivant le workflow via l'API Shuffle.
2. **Docker Swarm cassé** (résolution DNS interne défaillante) → repassé en mode `noswarm`.
3. **Réseau Docker isolé** (le conteneur d'action ne pouvait pas joindre TheHive) → ciblage de la passerelle Docker (`172.17.0.1`) plutôt qu'une IP de conteneur interne.
4. **Mauvais nom d'opérateur de condition** → recherche dans le SDK Python de Shuffle pour trouver les vrais opérateurs valides.
5. **Cache du déclencheur figé** → cycle Stop → Start du Webhook nécessaire après chaque modification.
6. **Bug d'instabilité du moteur Liquid** (collision de nom entre la variable `exec` et la fonction Python `exec()`) → bug amont non contournable ; les titres de cas restent statiques, mais sévérité et tags sont fiables à 100 %.
7. **Filtre `<level>` de Wazuh non respecté** par le bloc d'intégration → filtrage anti-bruit implémenté directement dans les conditions du workflow.
8. **Conteneurs/images Shuffle supprimés par effet de bord** d'un nettoyage disque Docker (`docker container/image prune`) sur des conteneurs arrêtés depuis 44h → redéployé depuis le code source ; le workflow a survécu car porté par un volume Docker séparé.

**Validation finale** : le workflow a été réexécuté réellement plusieurs fois au cours du projet (voir les sections [Preuve de bout en bout](#preuve-de-bout-en-bout--cinq-scénarios-du-cahier-des-charges) et [Approfondissement](#approfondissement--routage-automatique-par-criticité-sur-un-incident-unique)) — statuts `FINISHED` systématiques, cas TheHive vérifiés indépendamment via l'API à chaque fois.

## Dashboard SOC personnalisé

Un tableau de bord dédié (module Visualize/Dashboards de Wazuh/OpenSearch Dashboards) avec 4 indicateurs branchés sur les données réelles :

| Indicateur | Visualisation |
|---|---|
| Nombre total d'incidents (30j) | Métrique |
| Répartition des alertes par type | Barres verticales (top 10) |
| Répartition par criticité | Camembert |
| Techniques MITRE ATT&CK détectées | Tableau |

![Dashboard SOC personnalisé](docs/screenshots/kibana_soc_dashboard.png)

Sur 30 jours de données réelles : 1884 alertes, 9 techniques MITRE distinctes couvertes (T1078, T1021, T1548.003, T1040, T1110.001, T1021.004, T1499, T1136, T1531).

## Bugs et incidents réels — récapitulatif complet

Cette maquette a fait l'objet de plusieurs sessions de re-vérification active plutôt que de suppositions sur son bon fonctionnement continu. Récapitulatif complet des incidents d'infrastructure rencontrés à travers tout le projet, tous corrigés :

| Incident | Cause | Correction |
|---|---|---|
| Sous-dimensionnement CPU (2 → 4 vCPU) | `load average` 100+ sur 2 cœurs | `VBoxManage modifyvm --cpus 4` |
| Panne silencieuse Filebeat ↔ Indexer | Mot de passe indexeur changé, jamais répercuté | `INDEXER_PASSWORD` mis à jour + recréation des conteneurs |
| 4 plantages `wazuh_ai_triage.py` | Casse/langue de la criticité, JSON malformé, champs manquants | Normalisation, `format: "json"`, `.get()` avec valeur par défaut |
| OOM Ollama récurrent | RAM saturée par MISP/tenzir/dashboard en simultané | Arrêt temporaire des services non essentiels pendant le triage |
| `wazuh-analysisd` silencieux après reboot | Collecte `journald` de l'agent ne reprend pas seule | `sudo systemctl restart wazuh-agent` après chaque redémarrage manager |
| Décodeur `auditd` incompatible | Attend des enregistrements pré-fusionnés | Service `audit_merge.py` |
| Troncature `full_log` | Coupait le contenu `EXECVE` | 400 → 900 caractères |
| Caractères de contrôle dans les requêtes JSON | `auditd` insère `\x1d` | Regex de nettoyage |
| OOM à la 3ᵉ requête LLM | Cache de prompt Ollama cumulé | Arrêt temporaire TheHive/Cassandra/ES |
| Credential leak (mot de passe en clair dans l'index) | `curl -u user:pass` capturé par l'audit de commandes | Purge des documents, rotation du mot de passe, `~/.netrc` |
| 0 % MITRE sur 4 scénarios avancés | Hors distribution few-shot | 4 exemples few-shot ajoutés |
| Biais de description de règle | Mot "phishing" dans `rule.description` transmis au LLM | Reformulation de la règle |
| `temperature=0.0` empire le résultat | Contre-intuitif mais mesuré | Conservé à `0.1` |
| Règles `auditd` non persistantes au reboot | Pas de fichier dans `/etc/audit/rules.d/` | Règle écrite en dur + `augenrules --load` |
| OOM Gemma2 9B + stack TheHive | Modèle plus gros, RAM plus sollicitée | Séquencement TheHive arrêté/redémarré |
| 401 intermittents TheHive (`requests` Python) | Latence resynchronisation Cassandra | `curl` en sous-processus en attendant la stabilisation |
| Disque VM à 96 % | Images Docker obsolètes accumulées | Nettoyage Docker (9,2 Go libérés) |
| Conteneurs Shuffle supprimés par effet de bord | Nettoyage Docker sur conteneurs arrêtés 44h | Redéploiement depuis le code source |
| Bugs Shuffle (nœud fantôme, Swarm cassé, réseau isolé, opérateurs de condition, cache figé, bug Liquid, filtre `<level>`) | Voir section dédiée | Voir section dédiée |
| VM complètement gelée (~46 min, aucune réponse réseau) | RAM épuisée sans swap configuré, thrashing noyau | Redémarrage forcé (`VBoxManage poweroff` + `startvm`), tous les conteneurs configurés en restart automatique |
| Push automatique TheHive → MISP impossible (403 persistant) | Dysfonctionnement de l'authentification par clé API de cette instance MISP (cause non résolue malgré investigation dans le code source) | Non résolu — solution de repli : export MISP manuel natif de TheHive, fonctionnel |
| Volume de bruit `auditd` extrême (~14 000 alertes/15 min) | Règle `auditd` auditant aussi les process internes Docker (`runc`, `containerd`) | Filtrage par UID réel : `-F auid>=1000 -F auid!=4294967295` |
| Alertes significatives perdues sous le bruit dans `wazuh_ai_triage.py` | Filtrage par `rule.level` effectué côté client après récupération des N alertes les plus récentes | Filtre déplacé dans la requête Elasticsearch (`bool.filter` côté serveur) |
| `auditd` arrêté silencieusement pendant 12h+ | Disque VM saturé à 100 % | Nettoyage Docker + purge journaux + agrandissement disque VirtualBox 59→80 Go |
| Cassandra (TheHive) refuse de démarrer | Commit logs corrompus après arrêts brutaux répétés de la VM | Commit logs corrompus mis en quarantaine ; données SSTable déjà persistées non affectées |
| Indexeur Wazuh en état `RED`, ingestion bloquée | Shards corrompus (`codec footer mismatch`) après arrêts brutaux, aucun réplica sur ce cluster single-node | Suppression de l'index quotidien corrompu, recréation automatique par Wazuh |
| Intégration Shuffle disparue de `ossec.conf` (réapparition) | Perdue à nouveau après un redémarrage de VM | Ré-ajoutée ; vigilance sur le fichier `ossec.conf` qui contient légitimement 2 blocs `<ossec_config>` |
| Génération Gemma2 9B sans fin (OOM/blocages) | Aucune limite `num_predict` sur l'appel `/api/generate`, génération de tokens non bornée en mode JSON | `"num_predict": 300` ajouté aux options de génération |
| VM sous-dimensionnée pour l'inférence LLM (4 vCPU) | Hôte 8 cœurs/16 threads chargé à ~9 % seulement | `VBoxManage modifyvm "SOC-Lab" --cpus 8` |
| 401 Unauthorized TheHive via `requests` Python (`curl` identique réussit) | `requests` résout `localhost` en IPv6 (`::1`), authentification TheHive échoue silencieusement sur cette résolution | `THEHIVE_URL` fixé explicitement en IPv4 : `http://127.0.0.1:9000` |
| Cortex bloqué (jobs restant `Waiting` indéfiniment, UI ne répondant plus) | VM en mémoire quasi épuisée (111 Mo libres, swap à 100 %) après plusieurs cycles de triage Gemma sans libération intermédiaire | Déchargement du modèle Gemma (`keep_alive:0`) + redémarrage du conteneur Cortex |
| Image Docker de l'analyseur Cortex `VirusTotal_GetReport` introuvable | Même cause que pour `AbuseIPDB` plus haut (effet de bord d'un nettoyage Docker antérieur) | `docker pull ghcr.io/thehive-project/virustotal_getreport:3` |

## Limites d'infrastructure

Cette maquette tourne sur une VM initialement à 4 vCPU, portée à **8 vCPU / 9,7 Go de RAM** en cours de session pour absorber la charge d'inférence LLM. Sur cette configuration, faire tourner simultanément Wazuh (manager + indexeur + dashboard), TheHive (+ Cassandra + Elasticsearch), Cortex, MISP (+ MySQL + Redis), Shuffle et un LLM 9B reste **tendu** : `load average` observé jusqu'à 90 sur la configuration initiale à 4 cœurs, `oom-kill` répétés, disque saturé à 96 % à un moment. Une estimation réaliste pour un fonctionnement confortable et continu est de **16 à 24 Go de RAM**, avec un espace disque surveillé activement (purge régulière des images Docker obsolètes).

Le mode de travail qui s'est imposé au fil des sessions n'est donc pas un contournement ponctuel mais une méthode : arrêter les services non essentiels à la tâche du moment, exécuter, puis les redémarrer. Documenté ici explicitement plutôt que présenté comme un fonctionnement continu sans friction, qui ne correspondrait pas à la réalité observée.

**Sur le temps de traitement du LLM** : ~119 s/alerte avec Gemma2 9B sur cette VM de test contrainte (RAM/CPU partagés avec toute la stack). Ce chiffre est honnêtement rapporté tel quel plutôt que minimisé. En entreprise, avec une infrastructure dédiée (plus de vCPU sans contention, RAM plus rapide, potentiellement un GPU), ce temps diminuerait significativement — d'autant que l'architecture à deux niveaux ([voir plus haut](#renforcement-méthodologique)) garantit que le LLM n'est de toute façon jamais invoqué sur le flux brut complet, seulement sur les alertes déjà remontées comme significatives par la baseline.

## Reproduire l'environnement

Prérequis : VirtualBox, 16 Go de RAM recommandés (8 Go minimum en version réduite).

```bash
# 1. VM Ubuntu Server 22.04 + Docker (voir docker/)
# 2. Stack Wazuh officielle
git clone --depth 1 -b v4.10.1 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

# 3. TheHive
docker compose -f docker/thehive-docker-compose.yml up -d

# 4. Ollama + Gemma2 9B
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma2:9b-instruct-q4_0

# 5. Script d'intégration
pip install -r scripts/requirements.txt
python scripts/wazuh_ai_triage.py
```

## État d'avancement et planning

| Composant | Statut |
|---|---|
| Infrastructure (VM Ubuntu 22.04 + Docker, 8 vCPU / 9,7 Go RAM) | ✅ Opérationnel |
| Wazuh (Manager + Indexer + Dashboard + auditd) | ✅ Déployé, testé de bout en bout |
| TheHive 5.4 | ✅ Déployé, cas créés automatiquement (Shuffle et Gemma) |
| Ollama + Gemma2 9B (quantifié q4_0) | ✅ Déployé, triage testé et validé (100 % MITRE sur tous les scénarios avancés) |
| Script Python Wazuh → LLM → TheHive | ✅ Fonctionnel, réexécuté et vérifié en conditions réelles sur les 5 scénarios du cahier des charges |
| Jeu de 38+36 alertes labellisées + évaluation LLM vs baseline | ✅ Réalisé, répété 3 fois pour mesurer la variance |
| Cortex (analyse d'observables) | ✅ Déployé, analyseurs réels testés sur des IP/domaines réels des scénarios, connecteur TheHive lié et testé |
| MISP (Threat Intelligence) | ✅ Déployé, événement + IOC réels créés, connecteur TheHive lié et testé |
| Shuffle (SOAR) | ✅ Déployé, playbook à 3 étapes testé de bout en bout (webhook réel → cas TheHive vérifié) |
| Cinq scénarios du cahier des charges (brute force, phishing, PowerShell, mouvement latéral, C2) | ✅ Rejoués individuellement et documentés de bout en bout |
| Dashboard SOC personnalisé | ✅ 4 indicateurs opérationnels |
| Rapports PDF automatiques | ⏳ Prévu, restant à faire |

| Semaine | Phase | Statut |
|---|---|---|
| S1 | Cadrage, architecture, choix du périmètre | ✅ |
| S2 | SIEM (Wazuh + collecte logs) | ✅ |
| S3 | Gestion incidents (TheHive) | ✅ |
| S4 | Assistant IA (Ollama + LLM) | ✅ |
| S5 | Évaluation IA (baseline, métriques, itérations) | ✅ |
| S6 | Enrichissement (Cortex, MISP) | ✅ |
| S7 | Automatisation (Shuffle, dashboard) | ✅ |
| S8 | Scénarios avancés (auditd, changement de modèle, preuve de bout en bout, 5 scénarios du cahier des charges) | ✅ |
| S9 | Validation finale, rapport, soutenance | ⏳ |

## Valeur professionnelle

Ce projet couvre les compétences SOC Analyst Tier 1/2 (triage, mapping MITRE, corrélation), Détection Engineering (règles personnalisées, `auditd`), Automatisation SOC (Python, APIs, SOAR), et IA appliquée (évaluation mesurable et rigoureuse d'un LLM comme assistant de triage, avec comparaison de modèles), le tout sur une infrastructure Docker Compose reproductible et honnêtement documentée — y compris ses limites.

---

**Auteur :** Omar Babba — 4IIR, EMSI Tanger
**Encadrement :** Proposition de stage PFA 2025-2026
