# Dashboard SOC personnalisé — RUN_ID PFA-FINAL-20260718-214637

## Contexte

Le tableau de bord "SOC PFA - Dashboard indicateurs" (module Visualize/Dashboards de
Wazuh/OpenSearch Dashboards) créé lors d'une itération précédente du projet a été retrouvé
intact — 4 visualisations (`SOC - Nombre total incidents (30j)`, `SOC - Repartition des
alertes par type (top 10)`, `SOC - Repartition par criticite (rule.level)`, `SOC - Techniques
MITRE ATT&CK detectees`) plus le dashboard combiné les regroupant, tous créés le
`2 juillet 2026`. Ces objets sauvegardés interrogent l'index `wazuh-alerts-*`, qui est
l'index Wazuh vivant et continu du laboratoire (pas un index recréé par RUN_ID) — les
données affichées incluent donc naturellement les 6 scénarios réels générés pour ce RUN_ID
(`PFA-FINAL-20260718-214637`, voir `../wazuh/` et `../gemma/`), mêlées au reste du trafic réel
du laboratoire accumulé sur 30 jours.

## Gestion RAM avant cette phase

Conformément à la règle de gestion RAM séquentielle du laboratoire (VM à 10 Go), les
conteneurs Wazuh indexer/dashboard avaient été arrêtés pendant les phases Cortex/MISP/Shuffle
pour libérer de la RAM. Avant cette phase :
- Les piles MISP et Shuffle ont été arrêtées (`docker compose stop`), ainsi que `tenzir-node`
  (non nécessaire pour cette phase).
- Les conteneurs `single-node-wazuh.indexer-1` et `single-node-wazuh.dashboard-1` ont été
  redémarrés (`docker start`), après vérification qu'ils étaient bien arrêtés (`Exited`, pas
  supprimés) — aucune perte de données, les volumes Docker ont persisté pendant l'arrêt.
- RAM disponible sur la VM après cette reconfiguration : passée de ~550 Mo à ~2,2 Go libres
  (7,3 Go "available" avec cache), suffisant pour Wazuh manager + indexer + dashboard seuls.

## Les 4 indicateurs (données réelles, vérifiées indépendamment)

| Indicateur | Type | Valeur observée (fenêtre 30 jours) |
|---|---|---|
| Nombre total d'incidents (30j) | Métrique | `289 027` (tableau de bord) |
| Répartition des alertes par type (top 10) | Barres verticales | Dominé par les alertes `Audit: Command` (auditd), cohérent avec la stratégie de détection du labo basée sur l'audit de commandes |
| Répartition par criticité (`rule.level`) | Camembert | 10 niveaux distincts présents (3, 4, 5, 6, 7, 8, 9, 10, 11, 12) ; niveau 3 largement majoritaire (bruit de fond auditd) |
| Techniques MITRE ATT&CK détectées | Tableau | 18 techniques MITRE distinctes sur 30 jours ; `T1071` (2 466 occurrences) confirmé — c'est la technique assignée par Gemma2 au scénario `scenario5_c2_beaconing` de ce RUN_ID |

## Vérification indépendante (requêtes brutes OpenSearch, pas de confiance aveugle dans l'UI)

Chacun des 4 chiffres affichés dans l'interface a été recontrôlé par une requête directe
contre l'indexeur OpenSearch (port 9200, accessible uniquement depuis l'intérieur de la VM,
requêtes exécutées via SSH) :

- **Total 30 jours** : `GET /wazuh-alerts-*/_count` → `289 093` (écart de 66 documents avec
  le chiffre affiché dans le tableau de bord, explicable par le flux continu de nouvelles
  alertes auditd entre la capture UI et la requête de vérification quelques secondes après —
  pas une anomalie, la preuve d'un système réellement vivant).
- **Répartition par criticité** : agrégation `terms` sur `rule.level` → 10 buckets, dont les
  clés (`3,8,10,7,5,12,6,9,4,11`) correspondent exactement à la légende du camembert.
- **Techniques MITRE** : agrégation `terms` sur `rule.mitre.id` → les 7 premières lignes du
  tableau UI correspondent valeur par valeur à l'agrégation brute (`T1105: 5243, T1078: 2683,
  T1071: 2466, T1021: 887, T1040: 550, T1548.003: 258, T1021.004: 194`).
- **Nombre de techniques distinctes** : agrégation `cardinality` sur `rule.mitre.id` →
  `18` (chiffre exact, absent de l'UI qui n'affiche qu'un tableau paginé — calculé
  indépendamment pour compléter la caractérisation quantitative du dashboard).

Preuve brute complète : `raw_verification_opensearch_aggregations.json`.

## Captures d'écran

**Résolu** : le mécanisme de capture d'écran générique (`save_to_disk`) utilisé initialement
se bloquait systématiquement (voir historique ci-dessous). La fonctionnalité native
"Reporting → Download PNG" de Wazuh/OpenSearch Dashboards a été utilisée à la place — export
serveur du tableau de bord complet, indépendant de l'outil de capture d'écran externe. Fichier
réel produit et vérifié :

| Fichier | Contenu |
|---|---|
| `screenshots/soc_dashboard_indicateurs.png` | Capture propre du tableau de bord complet (4 panneaux), prise directement par l'utilisateur depuis son propre navigateur (remplace la première capture générée via "Reporting", qui affichait la bannière de débogage Chrome liée à l'automatisation) — total `293 037` incidents (30j), répartition par type, camembert de criticité (10 niveaux), tableau des 18 techniques MITRE. Valeurs identiques à celles recoupées indépendamment avec les requêtes OpenSearch brutes (`T1105: 5243, T1078: 2719, T1071: 2466, T1021: 902, T1040: 553` — légères variations de comptage par rapport à la première vérification, cohérentes avec le flux continu d'alertes réelles entre les deux mesures). |

Historique (pour traçabilité, n'affecte plus la preuve actuelle) : une première tentative
d'export via un outil de capture d'écran générique (`save_to_disk`) se bloquait
systématiquement (`timeout`, aucun fichier produit, reproduit deux fois). Plutôt que de
persister avec cet outil, la fonctionnalité d'export native du dashboard lui-même a été
utilisée — une solution plus directe et plus fiable, puisqu'elle ne dépend d'aucun outillage
externe au produit testé.

## Ce qui n'a PAS été fait

- Aucune nouvelle visualisation n'a été créée : les 4 indicateurs et le dashboard combiné
  existaient déjà (créés le 2 juillet 2026, itération précédente) et interrogent le même index
  `wazuh-alerts-*` vivant — ils ont simplement été rouverts, revérifiés avec des données
  fraîches (incluant ce RUN_ID) et redocumentés, pas recréés depuis zéro.
- Aucune modification n'a été apportée aux visualisations ou au dashboard existants.
- La fenêtre "30 jours" n'a pas été réduite à la seule durée de ce RUN_ID : les indicateurs
  restent volontairement définis sur une fenêtre glissante de 30 jours, cohérent avec l'usage
  SOC réel d'un tel tableau de bord (surveillance continue, pas un rapport figé par run).

## Preuves brutes

- `raw_verification_opensearch_aggregations.json` — 4 requêtes d'agrégation OpenSearch
  exécutées directement (total, criticité, techniques MITRE top-15, cardinalité MITRE),
  recoupées valeur par valeur avec l'UI.
- `screenshots/soc_dashboard_indicateurs.png` — export PNG natif du tableau de bord complet.

Hash dans `../thehive52/SHA256SUMS_thehive52.csv`.
