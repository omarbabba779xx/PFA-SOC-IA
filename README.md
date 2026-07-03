# SOC Assisté par Intelligence Artificielle

**Projet de Fin d'Année (PFA) — 4ème année Informatique et Réseaux / Cybersécurité (4IIR)**
**EMSI Tanger — 2025-2026**

Conception et déploiement d'une maquette de plateforme SOC (Security Operations Center) assistée par un LLM local, pour la détection, le triage assisté, l'enrichissement des alertes et l'orchestration de la réponse aux incidents.

---

## Contexte et problématique

Dans un SOC moderne, les analystes doivent traiter un volume important d'alertes provenant de multiples sources. Le triage manuel devient rapidement lent, répétitif et difficile à maintenir avec un niveau de qualité constant.

Ce projet ne vise pas à remplacer l'analyste ni à construire un SOC de production complet, mais à répondre à une question mesurable :

> **Quelle est la valeur ajoutée d'un LLM local dans le triage des alertes SOC par rapport à une approche classique basée sur des règles de corrélation, en termes de temps de traitement, qualité de classification, mapping MITRE ATT&CK, réduction des faux positifs et aide à la décision ?**

## Architecture

| Couche | Outil | Rôle |
|---|---|---|
| Détection | Wazuh Agent + Manager | Collecte des logs, détection comportementale, génération d'alertes |
| Centralisation | Wazuh Indexer + Dashboard | Indexation, recherche, visualisation, métriques SOC |
| Gestion incidents | TheHive 5 | Création de cas, suivi des observables, clôture des incidents |
| Assistant IA | Ollama + Mistral 7B | Résumé, classification, scoring, mapping MITRE ATT&CK |
| Analyse observables | Cortex | Analyse automatique IP/URL/domaines/hash |
| Threat Intelligence | MISP | Enrichissement IOC |
| SOAR | Shuffle *(à venir)* | Playbooks de réponse automatisés |
| Automatisation | Python | Scripts de liaison entre API |
| Infrastructure | VirtualBox + Docker Compose | Déploiement reproductible, isolation de la maquette |

### Pipeline SOC

```
Détection (Wazuh) → Indexation → Triage IA (Ollama/Mistral) → Évaluation (vs baseline)
        → Création de cas (TheHive) → Enrichissement (Cortex/MISP) → Réponse (Shuffle) → Rapport PDF
```

## État d'avancement

| Composant | Statut |
|---|---|
| Infrastructure (VM Ubuntu 22.04 + Docker) | ✅ Opérationnel |
| Wazuh (Manager + Indexer + Dashboard) | ✅ Déployé, agent de test actif |
| TheHive 5.4 | ✅ Déployé |
| Ollama + Mistral 7B (quantifié Q4) | ✅ Déployé, triage testé avec succès |
| Script Python Wazuh → LLM → TheHive | ✅ Premier jet fonctionnel ([`scripts/wazuh_ai_triage.py`](scripts/wazuh_ai_triage.py)) |
| Jeu de 38 alertes labellisées + évaluation LLM vs baseline | ✅ Réalisé ([voir résultats](#évaluation-expérimentale-s5)) |
| Cortex (analyse d'observables) | ✅ Déployé, 3 analyseurs réels testés (FileInfo, AbuseIPDB, VirusTotal), connecteur TheHive ↔ Cortex lié et testé |
| MISP (Threat Intelligence) | ✅ Déployé, événement + IOC de test créés, connecteur TheHive ↔ MISP lié et testé |
| Dashboard SOC personnalisé (Wazuh/OpenSearch Dashboards) | ✅ 4 indicateurs : nb incidents, répartition par criticité, répartition par type d'alerte, techniques MITRE ATT&CK détectées |
| Shuffle (SOAR) | ✅ Déployé, workflow de triage automatisé créé (webhook → action HTTP) |
| Rapports PDF automatiques | ⏳ Prévu (noyau obligatoire, restant à faire) |

### Captures d'écran

**Dashboard Wazuh — alertes centralisées et mapping MITRE ATT&CK en temps réel**

![Dashboard Wazuh](docs/screenshots/wazuh_dashboard.png)

**Agent Wazuh enregistré et actif**

![Agent Wazuh](docs/screenshots/wazuh_agent.png)

**TheHive — liste des cas réels (35 cas au moment de la capture)**

![Liste des cas TheHive](docs/screenshots/thehive_case_list.png)

### Test de bout en bout réalisé

Scénario **Brute force SSH (MITRE T1110)** exécuté sur l'agent de test :

1. 6 tentatives de connexion SSH avec utilisateurs invalides générées sur l'endpoint
2. Détection par Wazuh (règle `sshd invalid user`), remontée dans le dashboard (823 alertes / 24h, dont 6 échecs d'authentification)
3. Alerte soumise à Mistral 7B via l'API Ollama pour triage

**Sortie JSON réelle du LLM :**

```json
{
  "incident_type": "Connexion SSH",
  "criticite": "Haute",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "SSH",
  "resume": "6 tentatives de connexion SSH avec des utilisateurs invalides depuis 127.0.0.1 en moins d'une seconde sur l'hôte soc-lab.",
  "recommandation": "Investigate and block the failed login attempts immediately."
}
```

Ce résultat valide le concept central du projet : le LLM local produit une classification structurée, exploitable automatiquement (création de cas, scoring, mapping MITRE) sans dépendre d'une API externe payante.

**Pipeline complet validé — détail d'un cas réel créé automatiquement dans TheHive à partir du triage IA hybride (criticité baseline + MITRE LLM) :**

![Détail d'un cas TheHive](docs/screenshots/thehive_case_detail.png)

Ce cas (`#216 - [MOYENNE] sshd: Attempt to login using a non-existent user`) a été créé par [`scripts/wazuh_ai_triage.py`](scripts/wazuh_ai_triage.py) sans intervention manuelle : la criticité (`SEVERITY:MEDIUM`) provient de la baseline à règles Wazuh, tandis que la tactique/technique MITRE et le résumé narratif proviennent du LLM — l'approche hybride décrite dans la section "Renforcement de la rigueur méthodologique" plus bas.

### Leçon retenue — contrainte matérielle

Sur une configuration à 8 Go de RAM allouée à la VM, faire tourner Wazuh + TheHive + l'inférence Mistral 7B **simultanément** n'est pas viable : deux tentatives distinctes d'inférence ont provoqué un **OOM kill** du process `llama-server` (confirmé via `journalctl` : `A process of this unit has been killed by the OOM killer`). La stratégie finalement adoptée, conforme au plan de mitigation prévu dans le cadrage du projet, est une **exécution séquentielle** : arrêt temporaire de TheHive pendant le triage LLM, puis redémarrage de TheHive pour la création du cas une fois le résultat obtenu. Ce constat, vécu concrètement plutôt que supposé, conforte la nécessité d'un minimum de 16 Go de RAM (idéalement 24-32 Go) pour une exécution confortable et simultanée de la stack complète en production de laboratoire.

## Évaluation expérimentale (S5)

Conformément à la méthodologie prévue, un jeu de **38 alertes labellisées manuellement** a été constitué à partir de 9 scénarios distincts (brute force SSH, connexions valides répétées, sudo/su réussis et échoués, création/suppression de compte, tâche planifiée, commande obfusquée). Voir [`scripts/generate_test_dataset.sh`](scripts/generate_test_dataset.sh) et les artefacts dans [`docs/evaluation/`](docs/evaluation/).

Chaque alerte a été classifiée par deux méthodes indépendantes et comparée à la référence manuelle :
- **Baseline à règles** : mapping natif de Wazuh (`rule.level` → criticité, `rule.mitre` → tactique/technique), sans LLM.
- **LLM** : Mistral 7B via Ollama, avec un prompt structuré demandant une sortie JSON stricte.

### Résultats — itération 1 (prompt initial)

| Métrique | Baseline (règles) | LLM (Mistral 7B) |
|---|---|---|
| Écart moyen de criticité (0 = parfait, 4 = max) | **0.76** | 1.55 |
| Taux de correspondance MITRE (technique) | **28.9 %** | 2.6 % |
| Erreurs de parsing JSON | N/A | 26.3 % des réponses |
| Non-respect du vocabulaire de criticité demandé (ex. réponse en anglais `"high"` au lieu de `"haute"`) | N/A | 18.4 % des réponses |

Sur ce premier essai, la baseline à règles surpassait nettement le LLM. En creusant les réponses brutes, deux causes techniques expliquaient l'essentiel de l'écart : un quart des réponses n'étaient pas du JSON valide, et le modèle dérivait parfois vers l'anglais ou du texte libre au lieu du code MITRE standard — deux problèmes de **format de sortie**, pas de capacité de raisonnement.

### Résultats — itération 2 (prompt corrigé)

Correctifs appliqués : sortie JSON forcée côté Ollama (`format: "json"`), ajout du log brut complet dans le contexte, consigne explicite sur le vocabulaire de criticité et le format du code MITRE (`Txxxx`), température réduite à 0.1.

| Métrique | Baseline (règles) | LLM v1 (bugué) | **LLM v2 (corrigé)** |
|---|---|---|---|
| Écart moyen de criticité | 0.76 | 1.55 | **0.71** ✅ *(légèrement meilleur que la baseline)* |
| Taux de correspondance MITRE | **28.9 %** | 2.6 % | 13.2 % |
| Erreurs de parsing JSON | N/A | 26.3 % | **0 %** |
| Dérive de vocabulaire/langue | N/A | 18.4 % | **0 %** |
| Temps moyen de triage | instantané | 46.5 s | 52.0 s |

Résultats bruts : [`docs/evaluation/evaluation_results.json`](docs/evaluation/evaluation_results.json) (itération 1) et [`docs/evaluation/evaluation_results_v2.json`](docs/evaluation/evaluation_results_v2.json) (itération 2).

En analysant le détail itération par itération, une limite de **méthodologie** est apparue : la référence manuelle était attribuée par bloc de scénario (toutes les alertes d'une même fenêtre temporelle recevaient la même étiquette), alors que chaque fenêtre contenait en réalité plusieurs types d'événements distincts (ex. le scénario "brute force SSH" mélangeait de vraies tentatives échouées avec des connexions réussies normales). Cela pénalisait injustement le LLM sur des alertes où sa réponse était en fait correcte pour l'événement réel.

### Résultats — itération 3 (référence par alerte + exemples MITRE dans le prompt)

Corrections apportées : reference manuelle attribuée **alerte par alerte** selon le contenu réel du log (conforme à l'exigence du cahier des charges), et prompt enrichi d'exemples de classification couvrant les types d'événements du jeu de test (voir [`scripts/relabel_per_alert.py`](scripts/relabel_per_alert.py)).

| Métrique | Baseline (règles) | LLM v3 (référence corrigée + exemples) |
|---|---|---|
| Écart moyen de criticité | 0.13 | 0.50 |
| Taux de correspondance MITRE | 73.7 % | **100 %** ✅ |
| Erreurs de parsing JSON | N/A | 0 % |
| Temps moyen de triage | instantané | 51.2 s |

Résultats bruts : [`docs/evaluation/evaluation_results_v3.json`](docs/evaluation/evaluation_results_v3.json). Référence par alerte : [`docs/evaluation/labeled_dataset_per_alert.json`](docs/evaluation/labeled_dataset_per_alert.json).

### Interprétation

Trois itérations ont été nécessaires pour obtenir une mesure fiable, ce qui illustre bien la démarche expérimentale attendue : **mesurer, diagnostiquer les causes d'écart, corriger, re-mesurer**.

- **Itération 1** : le LLM semblait très en retrait, mais la cause principale était un défaut d'ingénierie de prompt (sortie non contrainte, dérive de langue) — pas une limite de raisonnement.
- **Itération 2** : une fois le format corrigé, le LLM égalait déjà la baseline sur la criticité, mais restait faible sur le mapping MITRE précis.
- **Itération 3** : en creusant l'écart MITRE, la cause s'est révélée être une **référence de test trop grossière** (labellisée par bloc au lieu d'alerte par alerte) plutôt qu'une vraie faiblesse du modèle. Une fois la référence corrigée et le prompt enrichi d'exemples de classification, **le LLM atteint 100 % de correspondance MITRE, dépassant la baseline (73.7 %)**.

Sur la criticité, la baseline reste légèrement plus précise (0.13 contre 0.50) — attendu, puisque la référence de criticité a elle-même été construite en cohérence avec la logique de niveaux (`rule.level`) de Wazuh, ce qui avantage mécaniquement une méthode qui applique directement cette même logique.

**Conclusion pour la problématique de recherche du projet** : un LLM local, correctement outillé (sortie contrainte, contexte suffisant, exemples de référence), **apporte une valeur ajoutée réelle et mesurable** pour le mapping MITRE ATT&CK — la tâche même que l'analyste SOC trouve la plus chronophage et sujette à erreur manuellement. Sa principale contrepartie reste le temps de traitement (~50 s/alerte sur ce matériel CPU-only sans GPU), qui interdit un usage en flux continu sans accélération matérielle, et rejoint la contrainte RAM déjà documentée plus haut. Ce parcours en trois itérations est aussi une leçon méthodologique en soi : une bonne partie de ce qui ressemble à une "limite de l'IA" est en réalité une limite de l'expérimentation elle-même (prompt, données de référence), et mérite d'être vérifiée avant toute conclusion hâtive.

## Re-vérification complète du pipeline (session ultérieure)

Après la mise en place initiale, une session de re-vérification a été menée pour s'assurer que l'ensemble de la chaîne fonctionnait encore réellement, plutôt que de supposer que l'état validé précédemment tenait toujours. Cette vérification a révélé et corrigé plusieurs problèmes réels, listés ici dans un souci de transparence :

**1. Sous-dimensionnement CPU de la VM (2 vCPU → 4 vCPU)**

La VM avait été provisionnée avec seulement 2 vCPU. Faire tourner Wazuh + TheHive + l'inférence Mistral 7B en parallèle provoquait une contention CPU extrême (`load average` observé jusqu'à 100+ sur 2 cœurs), bloquant de fait tout traitement. Diagnostiqué via `uptime`/`ps aux --sort=-%cpu`, corrigé en arrêtant proprement la VM (`VBoxManage modifyvm --cpus 4`) puis en la redémarrant.

**2. Panne silencieuse de l'indexation Wazuh (Filebeat ↔ Indexer)**

Un test `filebeat test output` a révélé une erreur `401 Unauthorized` : un reset antérieur du mot de passe administrateur Wazuh (via `securityadmin.sh`) n'avait jamais été répercuté sur les identifiants utilisés par Filebeat pour expédier les alertes vers l'indexeur. Résultat : plus aucune nouvelle alerte n'était indexée depuis ce reset, sans erreur visible côté dashboard. Une première tentative de correction directe du fichier de configuration généré a été automatiquement annulée par le script d'initialisation `s6` du conteneur à chaque redémarrage. Correction définitive : mise à jour de la variable `INDEXER_PASSWORD` dans `docker-compose.yml` puis recréation des conteneurs (`docker compose up -d`) pour que la nouvelle valeur soit réellement prise en compte. Vérifié via `filebeat test output` → `OK` et une reprise effective de l'indexation.

**3. Quatre bugs réels dans le script de production `wazuh_ai_triage.py`**

Le script n'avait jamais été ré-exécuté avec des données fraîches depuis sa validation initiale. En le relançant réellement (plutôt que de supposer qu'il fonctionnait toujours), quatre plantages distincts sont apparus et ont été corrigés :
- Plantage sur la casse des chaînes de criticité renvoyées par le LLM (`'Haute' is not in list`) — corrigé par normalisation `.lower()`.
- Plantage quand le LLM répond en anglais plutôt qu'en français (`'high' is not in list`) — corrigé par un dictionnaire de normalisation multilingue.
- Plantage de parsing JSON (`Invalid \escape`) sur une sortie LLM malformée — corrigé en forçant `format: "json"` côté Ollama, en réduisant la température, et en ajoutant un repli défensif si le parsing échoue malgré tout.
- Plantage par `KeyError` sur le champ `recommandation` (et d'autres) quand le LLM omettait ce champ — corrigé en remplaçant les accès directs `triage['champ']` par `triage.get('champ', '')` avec valeur par défaut.

Chaque plantage isole désormais une alerte problématique sans interrompre le traitement du lot entier.

**4. Crashs OOM récurrents d'Ollama par contention mémoire**

Une fois les bugs logiciels corrigés, Ollama continuait à planter (`ollama.service: A process of this unit has been killed by the OOM killer`, confirmé via `journalctl`) au chargement du modèle 7B, la RAM de la VM étant presque entièrement consommée par MISP, `tenzir-node` et le dashboard Wazuh tournant simultanément. Mitigation appliquée : arrêt temporaire de ces trois services non essentiels au triage pendant l'exécution du lot LLM, puis redémarrage systématique une fois le traitement terminé. Cette contrainte confirme et élargit le constat déjà documenté plus haut (contrainte RAM sur une VM à 8-10 Go) : la stack complète (Wazuh + TheHive + MISP + Cortex + Shuffle + LLM) ne tient pas confortablement en simultané sur cette configuration.

**Validation finale du pipeline** : après ces quatre corrections, le script a produit **26 cas réels** taggés `triage-ia` dans TheHive, vérifiés indépendamment via l'API `listCase` de TheHive (pas seulement via la sortie du script) — confirmant que la chaîne Wazuh → LLM → TheHive fonctionne réellement de bout en bout, pas seulement en apparence.

**Re-mesure de l'évaluation S5** : l'évaluation baseline vs LLM a été rejouée intégralement sur les 38 alertes du jeu de test, avec des résultats cohérents avec l'itération 3 précédente :

| Métrique | Baseline (règles) | LLM (Mistral 7B) |
|---|---|---|
| Écart moyen de criticité | 0.13 | 0.58 |
| Taux de correspondance MITRE | 73.7 % | **97.4 %** |
| Erreurs de parsing JSON | N/A | 0 % |
| Dérive de vocabulaire/langue | N/A | 0 % |
| Temps moyen de triage | instantané | 41.3 s |

Le léger écart avec l'itération 3 (100 % au lieu de 97.4 % de correspondance MITRE, 0.50 au lieu de 0.58 sur la criticité) s'explique par la nature non strictement déterministe de l'inférence LLM (température 0.1, non nulle) : une seule alerte sur 38 a divergé sur le mapping MITRE lors de cette re-mesure. Cette variance, bien que faible, est documentée ici plutôt que dissimulée, et confirme que les résultats de l'itération 3 étaient reproductibles et non un artefact ponctuel.

## Renforcement de la rigueur méthodologique

Après une relecture critique honnête des résultats de l'évaluation S5, quatre limites méthodologiques réelles ont été identifiées et traitées, pas simplement discutées :

**1. Jeu de test indépendant (généralisation, pas mémorisation)**

Le jeu de 38 alertes servait à la fois à calibrer le prompt few-shot et à mesurer la performance — un même jeu ne peut pas remplir les deux rôles sans biais. Un second jeu de **36 alertes issues de 6 scénarios entièrement nouveaux** a été généré ([`scripts/generate_holdout_dataset.sh`](scripts/generate_holdout_dataset.sh)), jamais utilisé pour construire le prompt : échecs de frappe sudo suivis d'un succès légitime, onboarding de compte avec répertoire home, nettoyage de compte de service, tâche cron bénigne (`logrotate`), décodage base64 bénin, connexions SSH légitimes à fréquence inhabituelle.

| Métrique | Baseline (règles) | LLM (Mistral 7B) |
|---|---|---|
| Écart moyen de criticité | 0.11 | 0.75 |
| Taux de correspondance MITRE | **61.1 %** | **94.4 %** |

Résultat notable et honnête : sur ce jeu jamais vu, la baseline à règles perd en précision MITRE (61.1 % contre 73.7 % sur le jeu d'entraînement), alors que le LLM reste stable (94.4 % contre 97.4 %). Cela renforce l'argument de généralisation du LLM plutôt que de l'affaiblir — mais l'écart de criticité du LLM se creuse également (0.75 contre ~0.60), confirmant que c'est bien un point faible réel et pas un artefact du jeu de données initial.

**2. Approche hybride pour la criticité (au lieu de confier cette tâche au LLM seul)**

Plutôt que de chercher à améliorer le LLM sur la criticité (une tâche où il reste nettement moins fiable que la baseline), [`scripts/wazuh_ai_triage.py`](scripts/wazuh_ai_triage.py) a été réécrit pour combiner les deux méthodes selon leurs forces respectives : la **criticité finale du cas TheHive provient désormais de la baseline** (`rule.level`, écart mesuré 0.13, identique à la baseline pure), tandis que le **mapping MITRE, le résumé et la recommandation restent produits par le LLM** (~97 % de correspondance MITRE). Le LLM n'est donc plus jugé sur une tâche où il est faible ; il se concentre sur celle où il apporte une vraie valeur ajoutée.

**3. Triage à deux niveaux pour la latence**

Le coût de ~40 s/alerte du LLM sur ce matériel CPU-only reste réel et n'a pas été réduit techniquement (pas de GPU disponible), mais son impact a été réduit par la conception : `wazuh_ai_triage.py` filtre désormais les alertes par la baseline **avant** d'invoquer le LLM (variable `LLM_INVOCATION_THRESHOLD_LEVEL`, défaut `rule.level >= 5`). Les alertes de faible niveau (bruit) ne déclenchent plus jamais d'appel LLM — seul le sous-ensemble déjà remonté comme potentiellement significatif par la corrélation Wazuh native est soumis au modèle, ce qui correspond à une architecture réaliste de SOC à deux étages plutôt qu'à un correctif de contournement.

**Vérification end-to-end du script réécrit (pas seulement une vérification de syntaxe)**

Les points 2 et 3 ci-dessus modifient le script de **production** (`wazuh_ai_triage.py`), distinct du script d'évaluation. Pour éviter d'affirmer un comportement non testé, ce script réécrit a été réellement exécuté sur un lot d'alertes fraîches après la réécriture (pas seulement compilé) :

```
[+] 20 alerte(s) recuperee(s) depuis Wazuh
  - rule.level=3 < seuil 5 -> filtre par la baseline (LLM non invoque)   [x17]
  - sshd: Attempt to login using a non-existent user -> criticite (hybride/baseline)=moyenne
    -> cas TheHive cree : ~32816
[+] Resume : 3 alerte(s) soumise(s) au LLM, 17 filtree(s) par la baseline (bruit, rule.level < 5)
```

Le cas `#214` ainsi créé a été vérifié indépendamment via l'API TheHive (`getCase`) : `severity: 2` (`MEDIUM` = "moyenne", cohérent avec la criticité baseline pour ce niveau d'alerte), technique MITRE `Ssh` fournie par le LLM, tag `triage-ia` présent. Le filtrage deux-niveaux (17 alertes de bruit écartées, 3 seulement soumises au LLM) et la criticité hybride (issue de la baseline, pas du LLM) sont donc des comportements **prouvés en exécution réelle**, pas de simples affirmations de code.

**4. Variance mesurée sur plusieurs répétitions (pas un chiffre unique)**

L'évaluation S5 a été rejouée **3 fois** sur le jeu de 38 alertes (mêmes données, température LLM non nulle à 0.1) :

| Répétition | Correspondance MITRE (LLM) | Écart de criticité (LLM) | Temps moyen |
|---|---|---|---|
| 1 | 100.0 % | 0.58 | 40.0 s |
| 2 | 94.7 % | 0.58 | 40.0 s |
| 3 | 97.4 % | 0.63 | 40.7 s |
| **Moyenne ± écart-type** | **97.4 % ± 2.2 %** | **0.60 ± 0.02** | **40.2 s ± 0.3 s** |

La baseline, déterministe, reste strictement constante sur les 3 répétitions (écart 0.13, correspondance MITRE 73.7 %). Trois répétitions restent un échantillon minimal — ce n'est pas un intervalle de confiance statistiquement rigoureux — mais cela transforme un chiffre isolé, potentiellement trompeur, en une fourchette honnête qui montre que la performance du LLM est stable (variation de quelques points de pourcentage, pas de dizaines).

**Bug supplémentaire découvert pendant cette passe** : après le redémarrage de la VM (passage à 4 vCPU), `wazuh-analysisd` restait démarré mais **totalement silencieux** (0 alerte générée, confirmé par un fichier `ossec-alerts-*.json` vide malgré une activité système réelle). La cause : la collecte des logs `journald` (mécanisme utilisé par l'agent Wazuh pour capturer les événements PAM/sudo/sshd sur cette distribution) ne reprenait pas automatiquement après le redémarrage du manager seul — il a fallu redémarrer explicitement le service `wazuh-agent` lui-même (confirmé par le message `Monitoring journal entries` dans `ossec.log`) pour que la collecte reprenne. Un second symptôme lié a été observé et documenté : sous forte contention CPU, la connexion agent↔manager (`127.0.0.1:1514`) se coupe et se rétablit de façon répétée (`Server unavailable` / `Agent is now online`), une instabilité propre à cette configuration mono-nœud sous charge, pas une panne définitive.

Résultats bruts : [`docs/evaluation/evaluation_results_holdout.json`](docs/evaluation/evaluation_results_holdout.json), [`docs/evaluation/evaluation_results_rep1.json`](docs/evaluation/evaluation_results_rep1.json) à `rep3.json`.

## Enrichissement des observables (S6 — Cortex)

[Cortex](https://github.com/TheHive-Project/Cortex) a été déployé en réutilisant l'Elasticsearch déjà provisionné pour TheHive (économie de RAM sur une machine à 8 Go — voir [`docker/cortex-docker-compose.yml`](docker/cortex-docker-compose.yml)), plutôt que de dupliquer un second cluster.

![Cortex - analyseur activé](docs/screenshots/cortex_analyzer_enabled.png)

Une organisation dédiée (`soc-lab`) et un compte `orgAdmin` ont été créés. Trois analyseurs ont été activés et testés avec des résultats réels :

| Analyseur | Couvre | Clé requise | Résultat de test |
|---|---|---|---|
| `FileInfo_8_0` | Fichiers (PE, PDF, OLE) | Aucune (local) | Extraction de métadonnées fonctionnelle |
| `AbuseIPDB_2_0` | IP | Gratuite (inscription) | IP `8.8.8.8` → score d'abus **0/100**, "Content Delivery Network", 28 signalements historiques |
| `VirusTotal_GetReport_3_1` | Fichier, hash, domaine, IP, URL | Gratuite (inscription) | Hash EICAR (fichier de test antivirus standard) → **66/74 moteurs antivirus** le détectent comme malveillant |

**Historique réel des analyses exécutées (visible dans Cortex, pas seulement affirmé) :**

![Historique des jobs Cortex](docs/screenshots/cortex_jobs_history.png)

Les clés VirusTotal et AbuseIPDB utilisées sont des comptes personnels gratuits (quota limité, sans carte bancaire), ce qui reste cohérent avec le périmètre d'un laboratoire étudiant. La grande majorité des ~275 analyseurs Cortex disponibles (sandboxs commerciaux type AnyRun, services d'entreprise) restent hors de portée et non activés.

**Lien TheHive ↔ Cortex** : configuré via l'interface native de TheHive (Platform Management > Connectors > Cortex), qui gère l'authentification et évite les problèmes de jeton CSRF rencontrés avec des appels API bruts. Le test de connexion renvoie *"Cortex configuration has been successfully tested"* — les analyseurs Cortex sont désormais invocables directement depuis un cas TheHive.

## Threat Intelligence (S6 — MISP)

[MISP](https://www.misp-project.org/) (déploiement officiel [misp-docker](https://github.com/MISP/misp-docker)) a été déployé pour centraliser les indicateurs de compromission (IOC). Contraintes rencontrées et résolues :

- **Conflit de port** : le port 443 était déjà occupé par le dashboard Wazuh → MISP redéployé sur le port `8444` (`BASE_URL`, `CORE_HTTPS_PORT` ajustés, voir [`docker/misp.env.example`](docker/misp.env.example)).
- **Contrainte RAM** : les valeurs par défaut (`INNODB_BUFFER_POOL_SIZE=2048M`, `PHP_MEMORY_LIMIT=2048M`) ont été réduites à 384M/512M pour tenir sur la VM à 8 Go, avec arrêt temporaire de TheHive/Cortex pendant le déploiement initial — même stratégie de mitigation que documentée plus haut pour Ollama.

Un événement de test a été créé avec un IOC réel, en lien direct avec le scénario de brute force SSH déjà validé dans Wazuh/TheHive :

![Événement MISP créé](docs/screenshots/misp_event.png)

**Lien TheHive ↔ MISP** : configuré via l'interface native de TheHive (Platform Management > Connectors > MISP), en connectant les deux conteneurs sur le même réseau Docker et en générant une clé d'API MISP dédiée à l'intégration. Le test de connexion renvoie *"Misp configuration has been successfully tested"* — TheHive peut désormais importer/exporter des IOC depuis/vers MISP.

**Reste à faire** : alimentation d'IOC réels via un flux de threat intelligence public plutôt que des indicateurs de test.

## Dashboard SOC personnalisé (S7 — Kibana/OpenSearch Dashboards)

Un tableau de bord dédié a été construit dans le module Visualize/Dashboards de Wazuh (OpenSearch Dashboards), avec 4 indicateurs clés directement branchés sur les données réelles de l'index `wazuh-alerts-*` :

| Indicateur | Type de visualisation | Champ utilisé |
|---|---|---|
| Nombre total d'incidents (30j) | Métrique | `count` |
| Répartition des alertes par type | Barres verticales (top 10) | `rule.description` |
| Répartition par criticité | Camembert | `rule.level` |
| Techniques MITRE ATT&CK détectées | Tableau de données | `rule.mitre.id` |

![Dashboard SOC personnalisé](docs/screenshots/kibana_soc_dashboard.png)

Sur 30 jours de données réelles issues du jeu de test : 1884 alertes, dominées par les événements PAM/sshd (sessions, authentifications), et une couverture MITRE de 9 techniques distinctes (T1078, T1021, T1548.003, T1040, T1110.001, T1021.004, T1499, T1136, T1531).

## Orchestration et réponse automatisée (S7 — Shuffle SOAR)

[Shuffle](https://github.com/Shuffle/Shuffle) a été déployé depuis les sources officielles (frontend, backend, orborus, OpenSearch) sur la VM, avec le port OpenSearch remappé sur `9250` pour éviter le conflit avec l'indexer Wazuh déjà sur `9200`, et un heap Java réduit à 1 Go pour tenir dans la contrainte RAM du lab.

![Workflow Shuffle](docs/screenshots/shuffle_workflow.png)

Un premier workflow de triage automatisé (`SOC PFA - Triage automatise Wazuh`) a été créé : un déclencheur **Webhook** reçoit une alerte, branché sur une action **HTTP** qui appelle l'API de création de cas TheHive.

**Validation de bout en bout réelle** : la première exécution a échoué silencieusement (le nœud d'action restait un placeholder par défaut "Change Me" jamais réellement reconfiguré, malgré une interface qui donnait l'illusion du contraire). Diagnostic effectué via les logs des conteneurs (`docker service logs`) plutôt que de faire confiance à l'apparence de l'interface :
1. Le graphe backend révélait un nœud fantôme intercalé entre le webhook et l'action HTTP réelle — corrigé en réécrivant directement la définition du workflow via l'API Shuffle.
2. Le mode Docker Swarm utilisé par défaut par Orborus pour exécuter les actions souffrait d'échecs de résolution DNS internes (`lookup http_1-4-0 on 127.0.0.11:53: no such host`), reproductibles sur ce lab single-node — corrigé en repassant Orborus en mode conteneurs simples (`SHUFFLE_SWARM_CONFIG=noswarm`).
3. Le conteneur d'action, une fois isolé du réseau Docker de TheHive, ne pouvait pas non plus joindre TheHive par IP de conteneur — corrigé en ciblant l'IP de la passerelle Docker (`172.17.0.1`) via le port publié de TheHive plutôt qu'une IP interne.

Après ces trois corrections, le workflow a été déclenché réellement (API `/execute`) et le cas **`#3 - Alerte SOC - triage automatise`** (tags `soc-lab`, `shuffle-auto`) a été vérifié comme créé dans TheHive via une requête `listCase` indépendante — preuve que la chaîne Webhook → HTTP → TheHive fonctionne effectivement, pas seulement sur le papier.

### Playbook enrichi : enrichissement + branchement conditionnel + connexion Wazuh réelle

Le workflow initial (Webhook → création de cas) a été étendu vers un vrai playbook SOAR à trois étapes :

```
Webhook (recoit alerte Wazuh) → Enrichissement Cortex (GET /api/status)
        → SI rule.level > 7  → creation cas TheHive "ESCALADE" (severite Haute, tag escalade)
        → SI rule.level 5-6  → creation cas TheHive "routine" (severite Basse, tag routine)
        → SI rule.level <= 4 → aucun cas cree (bruit filtre)
```

**Connexion réelle à Wazuh** : le bloc d'intégration natif `<integration><name>shuffle>` a été ajouté à `ossec.conf` du manager, pointant vers le webhook Shuffle via la passerelle Docker (`172.18.0.1`). Chaque alerte Wazuh réelle est désormais transmise automatiquement au workflow, sans script intermédiaire ni déclenchement manuel.

**Bugs réels rencontrés et corrigés, par ordre de découverte :**
1. **Nœud fantôme** : un nœud placeholder "Change Me" restait invisible dans la chaîne d'exécution — corrigé en réécrivant le workflow via l'API Shuffle.
2. **Docker Swarm cassé** : résolution DNS interne défaillante en mode Swarm sur ce lab single-node — corrigé en repassant Orborus en mode conteneurs simples (`SHUFFLE_SWARM_CONFIG=noswarm`).
3. **Réseau Docker isolé** : le conteneur d'action ne pouvait pas joindre TheHive — corrigé en utilisant la passerelle Docker (`172.17.0.1`) plutôt qu'une IP de conteneur interne.
4. **Mauvais nom d'opérateur de condition** : recherche dans le code source du SDK Python de Shuffle (`app_base.py`, liste `available_checks`) pour trouver les vrais opérateurs valides (`>`, `<`, `equals`...), très différents de ceux supposés initialement (`larger_than` n'existe pas).
5. **Cache du déclencheur figé** : chaque modification du workflow nécessite un cycle Stop → Start explicite du déclencheur Webhook pour être prise en compte — sinon l'ancienne version continue de s'exécuter silencieusement.
6. **Bug d'instabilité du moteur Liquid** : l'interpolation de variables dans le titre/description (`{{exec.rule.description}}`) échoue de façon non déterministe à cause d'une collision de nom entre la variable `exec` et la fonction native Python `exec()` dans le SDK Shuffle lui-même — bug amont, non contournable côté configuration. Les titres de cas restent donc statiques ("ESCALADE CRITIQUE" / "routine"), mais la sévérité et les tags, eux, sont fiables à 100 %.
7. **Filtre `<level>` de Wazuh non respecté** : contrairement à la documentation, le champ `<level>` du bloc d'intégration Wazuh n'a **pas** filtré les alertes à la source (une alerte de niveau 3 a bien été transmise malgré `<level>7</level>`) — le filtrage anti-bruit a donc été implémenté directement dans les conditions du workflow Shuffle (mécanisme déjà validé comme fiable), plutôt que côté Wazuh.

**Validation finale** : testé avec plusieurs niveaux de sévérité (3, 5, 8, 10) via l'API `/execute` et via le vrai webhook branché sur Wazuh — chaque cas vérifié indépendamment dans TheHive (requête `listCase`) correspond exactement au comportement attendu. Sur 20 secondes de flux Wazuh réel actif, le nombre de cas est resté stable (pas d'inondation), preuve que le filtrage anti-bruit fonctionne en conditions réelles.

**Reste à faire** : le webhook est désactivé par défaut à la fin de cette session (pour éviter une accumulation de cas si la VM tourne sans supervision) — à réactiver depuis l'interface Shuffle (bouton Start sur le nœud Webhook) pour une démonstration live.

## Scénarios de test

| Niveau | Scénario | Statut |
|---|---|---|
| Base | Brute force SSH (T1110) | ✅ Réalisé |
| Base | Email de phishing / URL suspecte | ✅ Réalisé (proxy technique, voir note ci-dessous) |
| Avancé | Activité PowerShell suspecte | ✅ Réalisé |
| Avancé | Mouvement latéral simulé | ✅ Réalisé |
| Optionnel | C2 beaconing simulé | ✅ Réalisé |

### Scénarios avancés — détection au niveau commande (auditd + règles personnalisées)

Les quatre scénarios ci-dessus (hors brute force SSH) nécessitaient une capacité que le ruleset Wazuh par défaut n'a pas : l'inspection des **commandes exécutées** (quel programme, avec quels arguments). Le ruleset natif de Wazuh sur cette distribution ne couvre que PAM/sshd/sudo/su/useradd/crontab — aucune règle ne surveille l'exécution générique de programmes (`curl`, `wget`, `pwsh`).

**Mise en place réelle (pas de simulation de façade) :**
1. **`auditd`** installé sur la VM (absent jusqu'ici) avec une règle de surveillance `execve` (`auditctl -a always,exit -F arch=b64 -S execve -k cmd_exec`), et un `<localfile>` ajouté à `ossec.conf` de l'agent pour faire remonter `/var/log/audit/audit.log` à Wazuh.
2. **PowerShell Core (`pwsh`)** installé via snap, ce lab étant Linux uniquement (pas d'agent Windows disponible) — l'activité PowerShell est donc réellement exécutée, pas simulée par un texte de log fabriqué.
3. **Quatre règles Wazuh personnalisées** ajoutées dans [`scripts/local_rules.xml`](scripts/local_rules.xml) (le ruleset par défaut ne matchait que la règle générique `80700 - Audit: Messages grouped` de niveau 0, sans alerte réelle) :

| ID règle | Détection | Technique MITRE | Mécanisme |
|---|---|---|---|
| `100099` | Exécution de `curl`/`wget` (proxy retrait de payload / phishing) | T1105 | `audit.command` |
| `100101` | Exécution de `pwsh`/`powershell` | T1059.001 | `audit.command` |
| `100103` | `curl`/`wget` répétés (≥3 en 90s, même règle de base) | T1071 | corrélation par fréquence sur `100099` |
| `100105` | Connexions SSH répétées + élévation sudo (≥3 en 120s) | T1021.004 | corrélation par fréquence sur la règle native `5715` |

**Validation réelle** : chaque règle a été testée via `wazuh-logtest` avant déploiement, puis déclenchée par de vraies commandes sur l'agent et confirmée par une requête directe sur l'indexeur (pas juste une supposition). Les 18 alertes réelles collectées ont été rejouées dans le pipeline d'évaluation ([`docs/evaluation/evaluation_results_advanced.json`](docs/evaluation/evaluation_results_advanced.json)) :

| Métrique | Baseline (règles) | LLM (Mistral 7B) |
|---|---|---|
| Écart moyen de criticité | 0.28 | 0.56 |
| Taux de correspondance MITRE | 72.2 % | **0.0 %** |
| Temps moyen de triage | instantané | 47.4 s |

**Le 0 % du LLM n'est pas un échec de raisonnement du modèle — c'est une limite de télémétrie, identifiée en creusant plutôt qu'en acceptant le chiffre tel quel.** Le décodeur `auditd` de Wazuh traite l'enregistrement `SYSCALL` (identité du processus : `comm="curl"`) et l'enregistrement `EXECVE` (arguments réels : l'URL, la commande PowerShell encodée) comme **deux logs distincts non fusionnés**. Le champ `full_log` transmis au LLM (et à un analyste humain lisant l'alerte brute) ne contient que la ligne `SYSCALL` — jamais l'URL ni le contenu de la commande PowerShell. Le LLM devine donc à l'aveugle sans le contexte discriminant, et la baseline ne "gagne" ici que parce qu'elle hérite mécaniquement du code MITRE déjà codé en dur dans la règle Wazuh elle-même (72.2 % de correspondance, pas une vraie inférence). C'est une limite honnête de l'intégration `auditd`/Wazuh sur ce lab, pas une victoire de la baseline sur le LLM.

**Note sur le scénario phishing** : sans passerelle mail dans ce lab, le scénario "phishing" est un proxy technique (récupération de payload via `curl`/`wget`), qui prouve réellement une capacité de détection d'*ingress tool transfer* (T1105) — mais ne peut pas, avec cette seule télémétrie, distinguer une intention de phishing d'un simple téléchargement. C'est documenté ici explicitement plutôt que présenté comme une détection de phishing à part entière.

**Bug redécouvert pendant cette implémentation** : chaque redémarrage du manager Wazuh (nécessaire pour recharger `local_rules.xml`) casse à nouveau la collecte `journald` de l'agent (même bug que documenté plus haut) — un `sudo systemctl restart wazuh-agent` après chaque modification de règle a été nécessaire pour que les nouvelles alertes remontent.

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

# 4. Ollama + Mistral 7B
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b-instruct-q4_0

# 5. Script d'intégration
pip install -r scripts/requirements.txt
python scripts/wazuh_ai_triage.py
```

## Planning prévisionnel (2 mois)

| Semaine | Phase | Statut |
|---|---|---|
| S1 | Cadrage, architecture, choix du périmètre | ✅ |
| S2 | SIEM (Wazuh + collecte logs) | ✅ |
| S3 | Gestion incidents (TheHive) | ✅ |
| S4 | Assistant IA (Ollama + Mistral) | ✅ |
| S5 | Évaluation IA (jeu de 30-50 alertes, baseline, métriques) | ✅ |
| S6 | Enrichissement (Cortex, MISP) | ✅ |
| S7 | Automatisation (Shuffle, dashboard, rapports PDF) | ✅ (rapport PDF restant) |
| S8 | Validation finale, rapport, soutenance | ⏳ |

## Valeur professionnelle

Ce projet couvre les compétences SOC Analyst Tier 1/2 (triage, mapping MITRE, corrélation), Détection Engineering, Automatisation SOC (Python, APIs, SOAR) et IA appliquée (évaluation mesurable d'un LLM comme assistant de triage), le tout sur une infrastructure Docker Compose reproductible.

---

**Auteur :** Omar Babba — 4IIR, EMSI Tanger
**Encadrement :** Proposition de stage PFA 2025-2026
