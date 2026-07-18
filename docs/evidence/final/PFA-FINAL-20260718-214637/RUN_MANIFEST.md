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

## Prochaine action

En attente d'un accès shell valide à la VM `SOC-Lab` pour reprendre à la Phase 1
(validation de la configuration Wazuh). Toutes les autres phases du plan de validation en
dépendent directement.
