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
| Analyse observables | Cortex *(à venir)* | Analyse automatique IP/URL/domaines/hash |
| Threat Intelligence | MISP *(à venir)* | Enrichissement IOC |
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
| Cortex / MISP / Shuffle | ⏳ Extensions prévues (S6-S7) |

### Captures d'écran

**Dashboard Wazuh — alertes centralisées et mapping MITRE ATT&CK en temps réel**

![Dashboard Wazuh](docs/screenshots/wazuh_dashboard.png)

**Agent Wazuh enregistré et actif**

![Agent Wazuh](docs/screenshots/wazuh_agent.png)

**TheHive — plateforme de gestion des incidents**

![TheHive](docs/screenshots/thehive_login.png)

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

**Pipeline complet validé — cas créé automatiquement dans TheHive à partir du triage IA :**

![Cas TheHive créé automatiquement](docs/screenshots/thehive_case_created.png)

Le cas `#1 - [HAUTE] alert - Brute force SSH (T1110)` a été créé par [`scripts/wazuh_ai_triage.py`](scripts/wazuh_ai_triage.py) sans intervention manuelle, avec sévérité, tags et mapping MITRE dérivés directement de la sortie du LLM.

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

### Interprétation

Une fois les problèmes de format corrigés, **le LLM égale voire dépasse légèrement la baseline sur l'estimation de la criticité** (0.71 contre 0.76), ce qui confirme qu'il est capable d'un jugement de gravité pertinent à partir du contexte brut d'une alerte — sans règle écrite à la main pour ce cas précis.

En revanche, le LLM reste **nettement en retrait sur le mapping MITRE technique exact** (13.2 % contre 28.9 %). C'est une limite structurelle attendue plutôt qu'un bug : la baseline Wazuh n'a pas besoin de "deviner" le code MITRE, elle le lit directement dans une table de correspondance écrite par des experts et associée à chaque règle de détection. Le LLM, lui, doit le retrouver de mémoire à partir du contexte, sans base de connaissances externe (pas de RAG dans cette version du projet). C'est une piste d'amélioration concrète et documentée pour la suite : coupler le LLM à une base de référence MITRE ATT&CK consultable (recherche vectorielle ou lookup direct) plutôt que de compter uniquement sur sa mémorisation.

**Conclusion pour la problématique de recherche du projet** : un LLM local mal outillé (sortie non contrainte) peut sembler moins fiable qu'une approche à règles — mais ce n'est pas une limite du modèle, c'est une limite d'ingénierie de prompt. Une fois corrigée, sa valeur ajoutée est réelle sur le jugement de criticité (tâche qui demande du contexte et du raisonnement), et clairement limitée sur le rappel de faits précis (mapping MITRE), un point où l'enrichissement par une base de connaissances externe serait la prochaine étape logique. Le temps de triage (~50 s/alerte sur ce matériel CPU-only) confirme par ailleurs qu'un usage en continu sur un flux d'alertes réel nécessiterait une accélération matérielle (GPU) ou un modèle plus léger.

## Scénarios de test

| Niveau | Scénario | Statut |
|---|---|---|
| Base | Brute force SSH (T1110) | ✅ Réalisé |
| Base | Email de phishing / URL suspecte | ⏳ Prévu |
| Avancé | Activité PowerShell suspecte | ⏳ Prévu |
| Avancé | Mouvement latéral simulé | ⏳ Prévu |
| Optionnel | C2 beaconing simulé | ⏳ Prévu |

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
| S5 | Évaluation IA (jeu de 30-50 alertes, baseline, métriques) | ⏳ |
| S6 | Enrichissement (Cortex, MISP) | ⏳ |
| S7 | Automatisation (Shuffle, dashboard, rapports PDF) | ⏳ |
| S8 | Validation finale, rapport, soutenance | ⏳ |

## Valeur professionnelle

Ce projet couvre les compétences SOC Analyst Tier 1/2 (triage, mapping MITRE, corrélation), Détection Engineering, Automatisation SOC (Python, APIs, SOAR) et IA appliquée (évaluation mesurable d'un LLM comme assistant de triage), le tout sur une infrastructure Docker Compose reproductible.

---

**Auteur :** Omar Babba — 4IIR, EMSI Tanger
**Encadrement :** Proposition de stage PFA 2025-2026
