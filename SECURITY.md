# Sécurité

Ce dépôt est le code source d'un **projet étudiant de laboratoire** (PFA,
4IIR EMSI Tanger). Il n'est ni destiné à un déploiement en production, ni
maintenu comme un projet open source à support continu.

## Choix de sécurité assumés pour un usage laboratoire

Documentés explicitement dans le README (section "Limites d'infrastructure")
et dans les commentaires des fichiers `docker/*.yml` concernés :

- `xpack.security.enabled=false` sur Elasticsearch (TheHive) — aucune
  authentification interne, réseau Docker isolé requis.
- Montage de `/var/run/docker.sock` dans le conteneur Cortex — nécessaire au
  fonctionnement natif de ses analyseurs, mais donne à Cortex un contrôle
  total sur le démon Docker de l'hôte.
- Tous les ports de services (`TheHive`, `Cortex`) sont liés à `127.0.0.1`
  uniquement dans les fichiers Compose fournis ; ne pas republier ces ports
  sur `0.0.0.0` sans ajouter une authentification en amont.

Ne jamais réutiliser cette configuration telle quelle sur un réseau non
isolé ou accessible depuis Internet.

## Signaler un problème

Ce dépôt n'a pas de programme de divulgation coordonnée. En cas de question
sur une configuration spécifique, ouvrir une issue GitHub sur le dépôt.
