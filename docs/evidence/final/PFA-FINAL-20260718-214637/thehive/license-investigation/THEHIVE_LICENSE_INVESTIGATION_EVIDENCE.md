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

## Logs

- `logs/thehive_capabilitysrv_full.log`

## Ce qui n'a PAS ete fait dans cette passe

- Aucun compte n'a ete supprime.
- Aucune migration de schema n'a ete lancee.
- Aucune activation de licence n'a ete tentee (en attente d'une licence
  Community officielle a fournir par l'utilisateur via le portail
  StrangeBee).
- Aucune instance TheHive isolee de diagnostic (Phase 7 du protocole) n'a
  ete montee — le lien de causalite schema/licence/CapabilitySrv reste donc
  partiellement indetermine, honnetement signale comme tel ci-dessus.
- Aucun compte administrateur n'a ete utilise pour contourner le controle
  (tous les tests de creation de cas ont utilise les comptes reels
  `soc-automation` et `analyst`, jamais `admin@thehive.local`).

## Conclusion actuelle

Les preuves API, logs et captures demontrent que l'instance TheHive
utilisait une licence synthetique `no-license` invalide, avec des quotas
d'ecriture nuls. Les comptes Normal et Service associes au profil analyst
recevaient tous deux un refus `403 manageCase/create`. Un desalignement des
versions de schema ainsi qu'une recursion dans l'initialisation de
CapabilitySrv ont egalement ete observes, cette derniere tracee jusqu'a un
echec de connexion Cassandra au demarrage. Aucune suppression, migration ou
activation de licence n'avait encore ete realisee au moment de ces captures.
