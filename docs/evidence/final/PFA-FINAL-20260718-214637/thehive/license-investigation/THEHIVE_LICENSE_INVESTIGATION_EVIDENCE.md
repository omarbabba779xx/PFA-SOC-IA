# Investigation TheHive — licence invalide et 403 manageCase/create

**RUN_ID** : `PFA-FINAL-20260718-214637`

## Objectif

Diagnostiquer pourquoi la creation de cas TheHive echoue systematiquement avec
`403 manageCase/create`, aussi bien pour le compte de service
(`soc-automation@thehive.local`) que pour le compte humain
(`analyst@thehive.local`), malgre un profil `analyst` correctement assigne
dans l'organisation `soc-lab`.

## Etat initial

- TheHive `5.4.11-1` (image `strangebee/thehive:5.4`), Cassandra `4.1`,
  Elasticsearch `7.17.24`.
- Deux comptes preexistants dans `soc-lab` : `analyst@thehive.local` (Normal)
  et `soc-automation@thehive.local` (Service), tous deux profil `analyst`.
- Le profil `analyst` (verifie via `/administration/entities/profiles`)
  contient bien `manageCase/create`, `manageCase/update`, `manageObservable`,
  `manageTask` — le profil lui-meme n'est pas casse.

## Comptes testes

| Compte | Type | Organisation | Profil | Resultat |
|---|---|---|---|---|
| `soc-automation@thehive.local` | Service | soc-lab | analyst | 403 `manageCase/create` |
| `analyst@thehive.local` | Normal | soc-lab | analyst | 403 `manageCase/create` (identique) |

## Endpoints testes

| Endpoint | Code HTTP | Resultat |
|---|---|---|
| `POST /api/v1/case` (soc-automation) | 403 | `manageCase/create` manquant |
| `POST /api/v1/case` (analyst) | 403 | `manageCase/create` manquant, meme erreur |
| `POST /api/v1/user` (nouveau compte Service) | 403 | `LicenseLimitExceeded users.service (1/0)` |
| `POST /api/v1/user` (nouveau compte Normal) | 403 | `LicenseLimitExceeded users.normal (1/0)` |
| `GET /api/v1/status` | 200 | `license.isValid: false`, `id: no-license` |
| `GET /api/v1/status?verbose=true` | 200 | `schemaStatus` desaligne (voir plus bas) |
| `GET /api/v1/license` | 200 | `[]` (liste vide) |
| `GET /api/v1/license/current` | 200 | `OutputLicenseCurrentNotFound`, fallback `no-license` a validite nulle |

## Licence — `no-license` confirme par l'endpoint officiel

```json
"license": {
  "id": "no-license",
  "plan": "No",
  "validFrom": 1784415536427,
  "expiresAt": 1784415536427,
  "isValid": false,
  "error": "The license is expired (valid from Sat Jul 18 22:58:56 UTC 2026 until Sat Jul 18 22:58:56 UTC 2026)",
  "quotas": {
    "users.normal": {"current": 1, "quota": 0},
    "users.service": {"current": 1, "quota": 0},
    "organisations": {"current": 1, "quota": 0}
  }
}
```

`validFrom == expiresAt` : une licence de secours a duree de validite nulle,
distincte de la licence trial Platinum mentionnee dans les logs de demarrage
initiaux (chargee le 2026-07-05, nominalement valide 15 jours). Les quotas
`1/0` pour `users.normal` et `users.service` expliquent a la fois le blocage
`manageCase/create` et l'impossibilite de creer un nouveau compte, quel que
soit son type.

## Desalignement de schema (trouve, lien de causalite avec la licence NON confirme)

```
thehive              currentVersion=98  expectedVersion=99
thehive-enterprise    currentVersion=93  expectedVersion=94
thehive-cortex         currentVersion=2  expectedVersion=3
```

## Erreur applicative — cause reelle identifiee (pas juste le symptome)

Symptome observe : boucle `TheHiveModule.capabilitySrv$lzycompute`
(TheHiveModule.scala:126), repetee des dizaines de fois dans les logs.

Premiere exception complete remontee jusqu'a sa cause racine :

```
org.thp.scalligraph.ScalligraphApplicationImpl$InitialisationFailure:
  Could not instantiate implementation: org.janusgraph.diskstorage.cql.CQLStoreManager
    at ScalligraphApplicationImpl.database$lzycompute
    at TheHiveModule.capabilitySrv$lzycompute(TheHiveModule.scala:126)

Caused by: java.lang.IllegalArgumentException:
  Could not instantiate implementation: CQLStoreManager

Caused by: com.datastax.oss.driver.api.core.AllNodesFailedException:
  Could not reach any contact point -- Node(/127.0.0.1:9042)

Caused by (racine) : java.net.ConnectException: Connection refused
```

**Conclusion honnete** : le symptome `capabilitySrv$lzycompute` est une
consequence d'un echec de connexion a Cassandra (port 9042) au demarrage de
TheHive, pas une erreur circulaire independante du composant CapabilitySrv.
Le lien de causalite exact avec l'etat `no-license` actuel n'est **pas**
demontre avec certitude — les deux pourraient partager une origine commune
(un demarrage de TheHive avant que Cassandra soit pleinement disponible,
survenu pendant les redemarrages effectues au cours de cette investigation),
mais cette hypothese n'a pas ete formellement verifiee par un test isole
(reproduction sur instance propre, non realisee dans cette passe).

## Verification "aucun privilege administratif" (comptes non-admin confirmes)

Les deux comptes testes (`soc-automation`, `analyst`) ont des profils
`analyst`, qui ne contient explicitement AUCUNE des permissions suivantes,
verifie sur l'objet profil complet recupere via
`/administration/entities/profiles` :
- `manageUser` — absent
- `manageProfile` — absent
- `manageOrganisation` — absent
- `managePlatform` — absent
- `manageConfig` — absent

## Captures d'ecran (voir SCREENSHOT_MANIFEST.csv pour les SHA-256)

| # | Fichier | Contenu |
|---|---|---|
| 1 | `01_..._thehive_current_state.png` | Vue principale, banniere licence invalide |
| 2 | `02_..._thehive_license_invalid_ui.png` | Page License Management : `No`, quotas rouges |
| 3a-c | `03[abc]_..._thehive_api_status_no_license_*.png` | Reponse complete `/api/v1/status` (3 parties) |
| 4 | `04_..._thehive_schema_mismatch.png` | `schemaStatus` desaligne |
| 5 | `05_..._thehive_accounts_profiles.png` | Organisation soc-lab, 2 comptes, profil analyst |
| 6 | `06_..._thehive_analyst_profile_permissions.png` | Profil analyst : permissions completes |
| 7 | `07_..._service_account_managecase_403.png` | 403 reel, compte Service |
| 8 | `08_..._human_analyst_managecase_403.png` | 403 reel identique, compte humain |
| 9 | `09_..._thehive_capabilitysrv_stacktrace.png` | Exception complete, cause Cassandra |

## Fichiers JSON bruts

- `raw/thehive_status.json`
- `raw/thehive_status_verbose.json`
- (diagnostic complet egalement dans `../diagnostic/`)
- `raw/thehive_status_relicensed.json` — `GET /api/v1/status` apres activation reelle de la licence Community (`isValid: true`).
- `raw/case_2169_unblock_test.json` — cas reel `~163848328` (`#2169`) cree via `POST /api/v1/case` avec le compte `analyst@thehive.local`, preuve que le blocage `403 manageCase/create` est leve.

## Logs

- `logs/thehive_capabilitysrv_full.log`

## Ce qui n'a PAS ete fait

- Aucun compte n'a ete supprime.
- Aucune migration de schema n'a ete lancee.
- Aucune instance TheHive isolee de diagnostic (Phase 7 du protocole) n'a
  ete montee — le lien de causalite schema/licence/CapabilitySrv observe
  initialement reste donc partiellement indetermine (mais sans plus
  d'impact operationnel, la licence etant desormais valide).
- Le test de deblocage a utilise le compte reel `analyst@thehive.local`
  (celui-la meme qui recevait le 403 documente plus haut), jamais
  `admin@thehive.local`, pour prouver que le deblocage s'applique bien au
  compte reellement bloque et pas seulement a un compte privilegie.
- Aucune credential StrangeBee (email/mot de passe du portail) n'a
  transite par un outil automatise ou un fichier de ce depot — le compte a
  ete cree et la licence generee entierement par l'utilisateur, dans son
  propre navigateur, hors de portee de l'assistant.

## Conclusion initiale (avant deblocage)

Les preuves API, logs et captures demontrent que l'instance TheHive
utilisait une licence synthetique `no-license` invalide, avec des quotas
d'ecriture nuls. Les comptes Normal et Service associes au profil analyst
recevaient tous deux un refus `403 manageCase/create`. Un desalignement des
versions de schema ainsi qu'une recursion dans l'initialisation de
CapabilitySrv ont egalement ete observes, cette derniere tracee jusqu'a un
echec de connexion Cassandra au demarrage. Aucune suppression, migration ou
activation de licence n'avait encore ete realisee au moment de ces captures.

## Mise a jour — licence obtenue et activee reellement (2026-07-20)

L'utilisateur a cree un compte StrangeBee personnel (`portal.apps.strangebee.com`,
`omar.babba@emsi-edu.ma`) et genere une licence Community reelle depuis le
portail officiel — aucun contournement, aucun patch binaire, aucune
falsification. Deroulement reel :

1. VM (`SOC-Lab`) redemarree (elle etait arretee au debut de cette phase).
2. Pile `thehive` (5.4.11-1 + Cassandra + Elasticsearch) redemarree
   (`docker compose start`, projet `/home/soc/thehive`) apres avoir libere de
   la RAM (arret de `tenzir-node`, non necessaire pour cette phase).
3. Connexion au compte super-admin (`admin@thehive.local`), navigation vers
   `Platform Management -> License -> Activate a license`.
4. Le "challenge" (jeton signe, lie a cette instance precise) genere par
   TheHive a ete copie via le bouton natif "Copy this challenge" (jamais
   affiche/tape manuellement) et colle par l'utilisateur dans le champ
   "License key activation challenge" du portail StrangeBee, sous la
   licence Community deja creee (`Plan: Community`, `Status: Pending`).
5. Apres soumission cote portail, un simple rechargement de la page
   `Platform Management -> License` a suffi : la licence etait deja
   appliquee automatiquement cote instance (mecanisme d'activation
   asynchrone StrangeBee <-> instance, aucune cle a copier-coller
   manuellement en retour).

### Verification reelle post-activation

- `GET /api/v1/status` (cle API du service, jamais affichee en clair) :
  `license.isValid: true`, `license.plan: "Community"`,
  `license.validFrom: 1784559376094` (2026-07-20T15:56:16Z),
  `license.expiresAt: 1816041600000` (2027-07-20). Preuve brute complete :
  `raw/thehive_status_relicensed.json`.
- **Test direct de l'action precedemment bloquee** : connexion en tant que
  `analyst@thehive.local` (compte reel de l'organisation `soc-lab`, celui-la
  meme qui recevait le 403 documente plus haut), puis
  `POST /api/v1/case` avec un titre explicite de verification ->
  **`201 Created`**, cas reel `~163848328` (`#2169`), `userPermissions`
  contient desormais `manageCase/create`. Preuve brute complete :
  `raw/case_2169_unblock_test.json`.
- Compteur de cas de l'organisation passe de 1975 a 1976 dans l'UI apres
  creation — coherent avec un vrai cas ajoute, pas un artefact d'affichage.

## Conclusion finale

Le blocage de licence documente ci-dessus est **resolu reellement**, pas
contourne. L'instance TheHive 5.4.11-1 dispose desormais d'une licence
Community valide et fonctionnelle (expiration 2027-07-20), et l'action
precisement bloquee a l'origine (`POST /api/v1/case` -> `403
manageCase/create`) a ete retestee avec le meme compte et reussit
desormais (`201 Created`). L'instance 5.2.16-1 isolee, deployee comme
solution de contournement pendant que ce blocage etait actif, reste
egalement operationnelle et n'a pas ete demantelee (aucune perte de
traçabilite).
