# Workflow Shuffle "Orchestration complete SOC-IA" — RUN_ID PFA-FINAL-20260718-214637

## Contexte

Nouveau workflow Shuffle construit pour donner à Shuffle un rôle réellement
actif dans le pipeline (pas seulement une preuve de concept vide), en réponse
au constat que les workflows précédents (`SOC PFA - Triage automatise Wazuh`
et les 3 workflows de la itération précédente) ne démontraient pas d'appel
HTTP réel bout-en-bout réussi.

Workflow : `PFA-FINAL-20260718-214637 - Orchestration complete SOC-IA`
(id Shuffle `8362f220-e5a1-4c18-b009-9d646f519e27`).

## Chaîne implémentée

```
Webhook_1 (trigger)
  -> http_1  : POST http://172.21.0.1:11434/api/generate   (Ollama / Gemma2 9B, triage IA)
  -> http_5  : POST http://172.21.0.1:9020/api/v1/case     (TheHive 5.2.16-1, creation de cas)
  -> http_6  : GET  http://172.21.0.1:9001/api/analyzer    (Cortex, listing des analyseurs)
```

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

## Ce qui n'a PAS été fait

- Le nœud Cortex (`http_6`) liste les analyseurs disponibles mais ne
  déclenche pas encore un job d'analyse complet sur un observable du cas
  TheHive (amélioration possible pour une itération suivante).
- Pas de nœud de condition/branchement sur la sévérité, ni de création MISP
  conditionnelle, ni de notification — seuls 3 des 5 points d'amélioration
  identifiés ont été implémentés dans le temps disponible pour cette passe.
