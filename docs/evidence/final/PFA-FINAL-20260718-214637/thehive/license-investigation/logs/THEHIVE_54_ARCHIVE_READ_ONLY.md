# THEHIVE_54_ARCHIVE_READ_ONLY

Geler le 2026-07-19T13:27:31Z. L'instance TheHive 5.4.11-1 (conteneurs thehive,
thehive-cassandra, thehive-elasticsearch) a ete arretee (docker stop, PAS supprimee)
apres avoir echoue a obtenir une licence Community valide via le portail StrangeBee
(indisponible pour ce compte/inscription). Elle est conservee comme archive historique :

- 3 sauvegardes de volumes completes et verifiees (voir volume_backup_log.txt) ;
- toutes les captures pre-correction (License, status, 403, schema, logs) ;
- reponses API brutes ;
- comptes et organisation existants NE SONT PAS reutilises dans la suite du RUN_ID.

Aucun conteneur de la nouvelle instance TheHive 5.2.16-1 ne doit se connecter aux
volumes thehive_cassandra-data, thehive_es-data ou thehive_thehive-data.

Decision documentee : le laboratoire TheHive 5.4 d'origine a complete ses tests
fonctionnels initiaux pendant la periode d'essai integree. Lors de la validation
finale, cette instance est passee en mode restreint car aucune licence Community
valide n'a pu etre activee via le portail requis. L'instance et ses preuves ont donc
ete preservees comme archive historique en lecture seule. Une instance TheHive 5.2.16
Community fraiche et isolee, anterieure a l'exigence d'activation via portail, a ete
deployee avec de nouvelles bases de donnees et de nouvelles preuves. Aucun mecanisme
de licence n'a ete contourne, modifie ou falsifie.
