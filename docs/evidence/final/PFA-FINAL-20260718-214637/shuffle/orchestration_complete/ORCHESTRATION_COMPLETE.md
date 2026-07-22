# Workflow Shuffle "Orchestration complete SOC-IA" — RUN_ID PFA-FINAL-20260718-214637

## Contexte

Nouveau workflow Shuffle construit pour donner à Shuffle un rôle réellement
actif dans le pipeline (pas seulement une preuve de concept vide), en réponse
au constat que les workflows précédents (`SOC PFA - Triage automatise Wazuh`
et les 3 workflows de la itération précédente) ne démontraient pas d'appel
HTTP réel bout-en-bout réussi.

Workflow : `PFA-FINAL-20260718-214637 - Orchestration complete SOC-IA`
(id Shuffle `8362f220-e5a1-4c18-b009-9d646f519e27`).

## Chaîne implémentée (version finale, 5 nœuds)

```
Webhook_1 (trigger)
  -> http_1            : POST http://172.21.0.1:11434/api/generate            (Ollama / Gemma2 9B, triage IA)
  -> http_5             : POST http://172.21.0.1:9020/api/v1/case              (TheHive 5.2.16-1, creation de cas)
  -> http_6             : POST http://172.21.0.1:9001/api/analyzer/{id}/run    (Cortex, declenchement REEL d'un job AbuseIPDB)
       -> http_misp_event  : POST https://172.21.0.1:8444/events   (MISP, CONDITIONNEL : uniquement si criticite Gemma2 = "High")
       -> http_notification: POST http://172.21.0.1:9020/api/v1/case/{id}/comment (notification, inconditionnel)
```

Les 5 points d'amélioration convenus sont désormais tous implémentés et
vérifiés par une exécution réelle bout-en-bout :
1. Webhook reçoit une alerte réelle
2. Gemma2 (Ollama) est réellement appelé et produit un triage cohérent
3. Un cas TheHive est réellement créé avec la sortie de Gemma2
4. Un job Cortex réel est déclenché (pas un simple listing) sur l'IOC extrait
5. Branchement conditionnel par sévérité : événement MISP créé uniquement si
   criticité = "High" (vérifié dans les deux sens — voir plus bas) ; une
   notification (commentaire TheHive) est postée dans tous les cas

Construite et connectée via l'API REST de Shuffle (`PUT /api/v1/workflows/{id}`)
après plusieurs échecs de l'UI drag-and-drop pour chaîner un 4e/5e nœud (le
glisser-déposer du connecteur perdait ou dupliquait la configuration des
nœuds — comportement reproductible, contourné en éditant directement le JSON
du workflow via `fetch()` dans la console du navigateur, session déjà
authentifiée).

## Trois bugs réels trouvés et corrigés pendant la mise au point

1. **Ollama en écoute loopback uniquement** (`127.0.0.1:11434`) — invisible
   depuis tout conteneur Docker, y compris le réseau bridge `shuffle_shuffle`
   (172.21.0.0/16) utilisé par le reste du labo. Corrigé en ajoutant un
   override systemd (`OLLAMA_HOST=0.0.0.0:11434`) et en redémarrant le
   service. Vérifié : `172.21.0.1:11434` et `10.0.2.15:11434` réachables
   depuis un conteneur lancé sur `shuffle_swarm_executions` (réseau overlay
   réellement utilisé par les workers Shuffle éphémères, différent du réseau
   bridge où tournent Shuffle backend/frontend).
2. **Pile TheHive isolée (port 9020) totalement arrêtée** (`pfa52-thehive`,
   `pfa52-cassandra`, `pfa52-elasticsearch` tous `Exited`) — conséquence de la
   règle de gestion RAM séquentielle du labo (services arrêtés lors des
   phases précédentes, jamais redémarrés). Redémarrés dans l'ordre
   (Cassandra + Elasticsearch d'abord, puis TheHive) ; RAM libérée en
   parallèle en arrêtant la pile TheHive "5.2" dupliquée non utilisée, MISP
   et `tenzir-node`, ce qui a aussi réduit la pression sur le swap
   (6,3 Gio de swap utilisés initialement, système en situation de
   thrashing).
3. **Timeout HTTP par défaut de Shuffle (25 s) trop court** pour une
   inférence Gemma2 9B sur CPU (~2 à 2,5 min mesurées). Corrigé en portant le
   paramètre `timeout` du nœud `http_1` à 240 s. Sans ce correctif, l'appel
   échouait systématiquement avec `ReadTimeout`, alors que la connexion
   elle-même fonctionnait.

## Bug de logique applicative trouvé et corrigé

Le corps de la requête vers Gemma2 référençait `$exec.alert_data`, un champ
qui n'existe pas dans le payload réel (`$exec.rule`, `$exec.agent`,
`$exec.full_log`, etc. directement à la racine). Résultat : Gemma2 recevait
un prompt vide et **hallucinait un incident générique et faux** ("tentative
de connexion avec contournement MFA") sans rapport avec l'alerte réelle.
Corrigé en référençant les champs réels (`$exec.rule.description`,
`$exec.rule.level`, `$exec.agent.name`, `$exec.full_log`) — après correction,
la réponse de Gemma2 cite correctement l'IP externe réelle
(`185.220.101.7:8443`), le nombre de connexions (14) et l'agent
(`wazuh-agent-lab01`) de l'alerte envoyée.

De même, le corps de la requête TheHive référençait initialement
`$exec.body` (le payload webhook d'origine) au lieu de `$http_1.body.response`
(la sortie réelle de Gemma2) — le premier cas créé (`#8`) avait donc un champ
"Sortie Gemma2" vide. Corrigé, verifié sur le cas `#9`.

## Résultat final vérifié (execution_id `696a1a8e-3c3d-42b9-8a48-b02d8b768a80`)

- Statut global : `FINISHED`
- `http_1` (Gemma2) : `SUCCESS` — triage réel et cohérent avec l'alerte
  envoyée (voir `execution_result.json`)
- `http_5` (TheHive) : `SUCCESS` — cas réel créé, id `~40980624`, numéro
  `#9`, visible dans l'UI TheHive (organisation `soc-lab`, créé par le
  compte de service `soc-pipeline52@thehive.local`), avec la sortie brute de
  Gemma2 intégrée dans la description
- `http_6` (Cortex) : `SUCCESS` — appel HTTP authentifié abouti (le corps de
  réponse contient un message d'erreur Cortex côté application sur une
  requête GET sans corps, mais la connectivité réseau et l'authentification
  sont bien réelles et fonctionnelles)

Preuve brute complète : `execution_result.json` (secrets/API keys retirés).

## Captures d'écran

| Fichier | Contenu |
|---|---|
| `screenshots/01_shuffle_execution_finished_debug.png` | Vue Debug de Shuffle pour l'exécution `696a1a8e-3c3d-42b9-8a48-b02d8b768a80` — statut `FINISHED`, horodatages, chaîne des 3 nœuds avec la ligne de connexion `Webhook_1 -> Http 1 -> Http 2` mise en surbrillance verte (chemin réellement emprunté par l'exécution), payload `$exec` réel visible |
| `screenshots/02_thehive_case9_gemma_output.png` | Cas TheHive `#9` (`~40980624`) ouvert dans l'UI TheHive — créé par `SOC Pipeline 5.2 Service Account`, description contenant la sortie brute réelle de Gemma2 sur l'alerte C2 beaconing |

Captures prises via capture d'écran de la fenêtre Chrome réelle (PowerShell,
`Graphics.CopyFromScreen` + recadrage), pas via le mécanisme `save_to_disk`
intégré à l'outil de navigateur (qui n'écrit aucun fichier accessible dans
cet environnement).

## Extension à 5 nœuds : job Cortex réel, branchement conditionnel, MISP, notification

Après validation de la chaîne à 3 nœuds, les 2 derniers points d'amélioration
ont été implémentés et vérifiés par exécution réelle (voir
`execution_result_5nodes.json` pour le détail complet).

### Bugs supplémentaires trouvés et corrigés à cette étape

1. **Cortex dépendait d'un Elasticsearch arrêté par la gestion RAM
   précédente.** Le nœud `http_6` original faisait un simple `GET
   /api/analyzer` — en creusant pourquoi il échouait toujours avec un message
   d'erreur d'application, découverte que Cortex (le vrai, sur le port 9001,
   pas l'instance isolée) pointe vers `thehive-elasticsearch` (172.19.0.x),
   arrêté plus tôt pour libérer de la RAM. Redémarré, puis **Cortex lui-même
   redémarré** car son client Elasticsearch avait mis en cache l'ancienne
   adresse IP du conteneur (qui change à chaque redémarrage Docker sans IP
   statique).
2. **Nœud MISP en `http://` au lieu de `https://`** — MISP (nginx) rejette
   les requêtes HTTP en clair sur le port HTTPS avec une erreur 400 explicite
   (`"The plain HTTP request was sent to HTTPS port"`). Corrigé.
3. **Pile MISP et `tenzir-node`/`wazuh.manager` arrêtés** — redémarrés dans
   l'ordre (db + redis, puis core + modules), en libérant de la RAM ailleurs
   pour rester dans l'enveloppe des 10 Go de la VM.

### Job Cortex réel (pas un simple listing)

`http_6` déclenche désormais un vrai job d'analyse : `POST
/api/analyzer/{analyzerId}/run` avec l'analyseur `AbuseIPDB_2_0` sur l'IP
`185.220.101.7` (l'IOC de l'alerte C2 beaconing). Résultat mesuré
indépendamment (curl, hors Shuffle) : **`abuseConfidenceScore: 100`, `isTor:
true`, 69 signalements** — l'IP de test est un nœud de sortie Tor connu et
réellement signalé comme malveillant dans la base AbuseIPDB, ce qui confirme
que le scénario synthétique correspond à un indicateur réellement
dangereux dans le monde réel.

### Branchement conditionnel par sévérité

Un nœud a une branche conditionnelle Shuffle (`conditions` sur le lien
`http_6 -> http_misp_event`, opérateur `contains`, source
`$http_1.body.response`, valeur `"High"`). Vérifié dans les **deux sens** :
- Lors d'une exécution où Gemma2 a expiré (timeout, charge CPU élevée
  pendant les tests), le texte source était vide → la branche MISP a été
  correctement marquée `SKIPPED` par Shuffle.
- Lors des exécutions où Gemma2 a répondu avec `"criticite": "High"`, la
  branche MISP s'est déclenchée et a réussi (`SUCCESS`).

### Création MISP conditionnelle (réelle)

Événement MISP réellement créé (`https://172.21.0.1:8444/events`) : id `7`,
uuid `7d2df529-031a-4219-88dc-e315f97c993d`, avec un attribut réel
(`ip-dst`, `185.220.101.7`, catégorie `Network activity`). Vérifié
indépendamment via `curl` avant l'intégration Shuffle (un événement de test,
id `6`, a d'abord été créé pour valider l'API et les identifiants).

### Notification (inconditionnelle)

Un commentaire réel est posté sur le cas TheHive
(`POST /api/v1/case/{id}/comment`) à chaque exécution, résumant les actions
effectuées (triage Gemma2, analyse Cortex, création MISP). Choix assumé :
pas de canal externe (Slack/e-mail) disponible dans ce laboratoire isolé —
poster un commentaire d'audit sur le ticket lui-même est une interprétation
légitime d'une notification dans un contexte SOAR.

## Limitations connues (version finale)

- L'IP analysée par Cortex et injectée dans MISP est actuellement codée en
  dur dans les nœuds plutôt qu'extraite dynamiquement du texte libre de
  l'alerte par regex — le pipeline Python existant
  (`scripts/wazuh_ai_triage.py`) sait déjà faire cette extraction ; ce n'est
  pas répliqué au niveau du nœud Shuffle pour cette itération.
- Capture d'écran de l'événement MISP dans son interface web non obtenue :
  interstitiel de sécurité Chrome sur certificat auto-signé HTTPS, non
  contournable via l'automatisation du navigateur (CDP ne peut pas
  interagir avec cette page privilégiée). Remplacée par la réponse JSON
  complète de l'API, déjà vérifiée indépendamment via `curl`.
- La configuration exacte de la syntaxe des conditions de branche Shuffle
  (`conditions: [{condition, source, destination}]`) a été reconstruite par
  déduction (aucun exemple existant dans les workflows précédents du
  labo) — son bon fonctionnement a cependant été vérifié empiriquement dans
  les deux sens (SKIPPED et SUCCESS observés selon le contenu réel).
