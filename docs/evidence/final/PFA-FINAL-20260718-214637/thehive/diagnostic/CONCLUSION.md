# Conclusion — état de licence TheHive (RUN_ID PFA-FINAL-20260718-214637)

L'instance TheHive fonctionne avec une licence synthétique de secours `no-license`.
L'endpoint officiel `/api/v1/status` retourne `isValid:false`, une erreur explicite
d'expiration et des quotas nuls. Cette situation suffit à expliquer les refus
d'écriture et les réponses 403 observées. Un désalignement de schéma a également été
découvert, mais son lien causal avec la licence n'est pas encore démontré.

Les quotas actuellement affichés appartiennent à la licence de secours `no-license`,
pas à une licence Community active.

Non affirmé (volontairement) :
- que CapabilitySrv est definitivement la cause racine
- que la migration de schema restaurera automatiquement la licence
- que l'ancien compte Service est corrompu
- que le profil analyst est casse
- que la licence Community limite normalement les comptes Service a zero
