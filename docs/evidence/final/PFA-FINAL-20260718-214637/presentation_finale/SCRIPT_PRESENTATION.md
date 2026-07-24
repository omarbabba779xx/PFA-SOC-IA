# Script de présentation — PFA SOC Assisté par IA

**Format** : discours continu, formel, à lire naturellement à l'oral. Chaque section correspond à une slide, mais le texte est écrit pour s'enchaîner sans rupture, comme une seule prise de parole.

---

## ANNEXE — Question anticipée (préparation orale, NE PAS mettre dans les slides)

**Q : Comment avez-vous exécuté concrètement l'attaque de C2 beaconing ?**

Techniquement, j'ai simulé le comportement réseau typique d'une machine compromise qui communique périodiquement avec un serveur de commande et contrôle, en exécutant sur la VM du laboratoire, en tant qu'utilisateur normal, la commande suivante : trois requêtes HTTP identiques envoyées vers la même destination externe, espacées de deux secondes, ce qui correspond exactement au pattern caractéristique d'un beaconing C2. Ce comportement est capturé par auditd, qui journalise chaque appel système execve avec sa ligne de commande complète. Ma règle Wazuh personnalisée corrèle ensuite ces événements : lorsque le même argument de destination apparaît trois fois dans une fenêtre de quatre-vingt-dix secondes, l'alerte se déclenche automatiquement avec la technique MITRE T1071. L'adresse IP utilisée n'est qu'un exemple pédagogique dans un environnement isolé, avec un délai d'attente très court, de sorte qu'aucune requête ne sort réellement vers une infrastructure externe : seul le comportement local, c'est-à-dire l'appel système répété, est ce qui compte pour la détection.

---

## Ouverture

Bonjour à tous. Avant de commencer, je tiens à remercier sincèrement Monsieur Tarek et Monsieur Amine pour leur encadrement, leur disponibilité et le temps qu'ils ont consacré au suivi de ce projet tout au long de l'année, car leurs retours m'ont permis de structurer une démarche rigoureuse et d'aller au bout d'une réalisation technique complète. Je me présente, Omar Babba, étudiant en quatrième année Ingénierie Informatique et Réseaux à l'EMSI Tanger. Mon intérêt pour le métier de SOC Analyst s'est construit progressivement au cours de ma formation, car c'est un métier qui exige une maîtrise concrète des outils de détection, de gestion d'incidents et de renseignement sur la menace, et non pas seulement une connaissance théorique. C'est cette conviction qui m'a poussé, à travers ce projet de fin d'année, à manipuler moi-même, de bout en bout, la chaîne d'outils qu'un SOC utilise réellement en production. Le choix du sujet n'est d'ailleurs pas anodin, puisqu'il répond à une tendance forte du secteur : les entreprises s'intéressent aujourd'hui de plus en plus à l'intégration de l'intelligence artificielle dans les opérations de sécurité, avec un objectif précis, celui de réduire le taux de faux positifs et de faux négatifs, et par conséquent de réduire la fatigue des analystes, un phénomène bien connu où un professionnel submergé d'alertes finit par en ignorer certaines, y compris de véritables menaces. C'est exactement cette problématique que mon projet cherche à adresser, en automatisant le triage initial d'une alerte grâce à un modèle de langage local, de sorte que l'analyste humain reçoive un dossier déjà qualifié plutôt qu'un flux brut à trier manuellement. Je vais donc vous présenter cette réalisation dans son ensemble, en suivant la logique exacte du pipeline que j'ai construit.

---

## Slide 1 — Titre

Ce projet s'intitule SOC Assisté par Intelligence Artificielle, et il couvre l'intégralité d'une chaîne de traitement d'incident : la détection par Wazuh, le triage automatisé par un modèle Gemma2 exécuté localement, la création de cas dans TheHive, l'enrichissement par Cortex, le partage de renseignement via MISP, puis la notification finale. J'insiste sur un point avant d'entrer dans le détail : l'ensemble de ce que je vais vous montrer aujourd'hui a été testé et exécuté ce jour même, avec des données réelles, sous un identifiant de run unique que vous verrez apparaître dans plusieurs captures. Il ne s'agit donc ni d'une simulation ni d'une maquette, mais bien de l'exécution réelle du pipeline sur mon infrastructure de laboratoire.

---

## Slide 2 — Chaîne logique du pipeline

Pour que la suite de cette présentation soit facile à suivre, je souhaite d'abord vous présenter la logique d'ensemble du pipeline, qui s'articule en sept étapes cohérentes. Tout commence avec Wazuh qui, grâce au module auditd, surveille en continu l'activité système de l'agent et détecte un comportement suspect. Cette alerte réelle déclenche ensuite automatiquement le workflow d'orchestration Shuffle par l'intermédiaire d'un webhook, qui transmet à son tour l'alerte à Gemma2, un modèle de langage exécuté localement via Ollama, chargé de réaliser le triage initial en déterminant le type d'incident, la technique MITRE ATT&CK correspondante et une estimation de criticité. Sur cette base, TheHive crée automatiquement un cas d'investigation contenant ce triage, pendant que Cortex enrichit en parallèle l'indicateur de compromission extrait de l'alerte, par exemple à travers une analyse de réputation d'adresse IP. Selon la sévérité retenue, et j'y reviendrai en détail un peu plus loin car ce point mérite une explication précise, un événement MISP est créé pour les alertes critiques, ou bien un simple tag est appliqué pour les alertes de faible sévérité, avant qu'une notification finale ne vienne clôturer l'ensemble du cycle. Un point d'architecture me semble important à souligner dès maintenant : chaque étape critique de ce pipeline est protégée par une garde de statut HTTP, un mécanisme que j'ai conçu moi-même après avoir constaté, en conditions réelles, qu'un outil pouvait techniquement répondre sans que l'action métier correspondante n'ait réellement abouti. Je détaillerai ce mécanisme lorsque nous arriverons à la slide consacrée à l'orchestration.

---

## Slide 3 — Wazuh détecte

Voici donc le tableau de bord Wazuh tel qu'il se présente en conditions réelles, avec l'agent actif et les alertes classées par niveau de sévérité. Wazuh constitue la première ligne de détection de mon SOC, dans la mesure où il collecte les journaux système et d'audit de l'agent surveillé, applique un ensemble de règles de corrélation, certaines standards et d'autres que j'ai écrites moi-même pour des scénarios spécifiques comme le beaconing C2, puis génère une alerte dès qu'un comportement correspond à une signature de menace connue.

---

## Slide 4 — Alerte réelle déclenchée

Voici précisément l'alerte qui a servi de point de départ au test que je m'apprête à vous détailler. Il s'agit de la règle que j'ai développée pour détecter un beaconing C2, c'est-à-dire des requêtes réseau répétées vers une même destination externe dans une fenêtre de temps courte, un comportement caractéristique d'une machine compromise communiquant avec un serveur de commande et de contrôle. Cette règle correspond à la technique MITRE ATT&CK T1071, et c'est bien cette alerte, réellement générée par Wazuh, que j'ai laissée déclencher l'ensemble du pipeline que je vais maintenant vous présenter.

---

## Slide 5 — Shuffle reçoit l'alerte et orchestre

Nous arrivons ici au cœur technique de ce projet, à savoir l'orchestrateur SOAR Shuffle, qui reçoit l'alerte via un webhook et pilote automatiquement l'ensemble de la chaîne de réponse. Le workflow que vous voyez à l'écran comporte treize éléments au total : un déclencheur webhook en point d'entrée, puis douze nœuds d'action, eux-mêmes répartis en deux catégories complémentaires. La première catégorie regroupe les six nœuds métier qui exécutent la logique fonctionnelle du pipeline, à savoir l'appel à Gemma2 pour le triage, la création de cas dans TheHive, l'appel à l'analyzer Cortex, la création d'événement MISP, le tag pour les alertes de faible sévérité, et enfin la notification finale. La seconde catégorie regroupe six gardes d'échec, une pour chaque nœud métier critique, et leur existence répond à une observation précise que j'ai faite en conditions réelles : un nœud HTTP dans Shuffle est marqué comme réussi dès que la requête réseau aboutit, même si le service distant renvoie en réalité une erreur applicative. Sans garde supplémentaire, le workflow pouvait donc continuer à s'exécuter en croyant qu'une étape avait réussi alors qu'elle avait échoué côté serveur, ce qui m'a conduit à ajouter, après chaque nœud métier critique, une condition vérifiant explicitement le code de statut HTTP réel contenu dans la réponse. Lorsque ce code est inférieur à trois cents, le chemin normal se poursuit, et lorsqu'il dépasse deux cent quatre-vingt-dix-neuf, l'exécution bascule vers un nœud d'échec dédié qui journalise l'erreur et empêche toute action incohérente en aval. J'ai d'ailleurs pu vérifier ce mécanisme en conditions réelles, notamment lors d'un test où TheHive a renvoyé une erreur d'authentification suite à un jeton invalide, et la garde s'est alors déclenchée correctement en stoppant la suite du traitement. Les conditions visibles sur les liens entre les nœuds sont donc de deux natures, des conditions de statut HTTP que je viens de décrire, ainsi qu'une condition de branchement métier sur la sévérité entre le nœud Cortex et la suite du pipeline, qui détermine si l'on part vers MISP ou vers le tag de faible sévérité, sur la base du niveau de risque calculé par Wazuh.

---

## Slide 6 — Triage par IA (Gemma2 9B)

Voici à présent la configuration réelle du nœud qui interroge le modèle de langage. J'utilise Gemma2 9B, quantifié et exécuté localement via Ollama, ce qui signifie qu'aucune donnée ne sort de mon infrastructure, un point important dans un contexte SOC où la confidentialité des alertes est sensible. Le prompt envoyé demande au modèle de répondre strictement en JSON avec quatre champs, le type d'incident, la criticité estimée, la tactique MITRE et la technique MITRE correspondante. Je souhaite être transparent sur un point technique que je juge important : le temps d'analyse par alerte a varié, dans mes tests réels d'aujourd'hui, entre environ cinquante secondes et un peu plus de quatre minutes, et cette variation s'explique entièrement par une contrainte d'infrastructure plutôt que par le modèle lui-même. Ma machine dispose en effet de seize gigaoctets de RAM au total, dont seulement dix sont réservés à la VM de laboratoire, qui doivent être partagés simultanément entre Wazuh, TheHive, Cortex, MISP, Shuffle et le modèle Gemma2. Pour gérer cette contrainte, j'ai donc dû faire fonctionner les outils de façon enchaînée plutôt qu'en parallèle permanent, en libérant de la mémoire entre chaque étape, alors que dans une infrastructure d'entreprise disposant de ressources dédiées et plus importantes, ce temps de traitement serait considérablement réduit et l'ensemble des outils pourrait tourner en continu sans cette gestion manuelle de la charge. Sur le fond, cela dit, le modèle s'est montré particulièrement fiable dans mes tests de triage, puisqu'il a systématiquement identifié la bonne tactique et la bonne technique MITRE ATT&CK correspondant au scénario réel. J'ajoute un dernier point d'architecture qui me semble essentiel à mentionner ici : la criticité qui détermine la branche empruntée par la suite du workflow n'est pas celle proposée par Gemma2, mais celle du baseline natif de Wazuh, c'est-à-dire un niveau de règle déterminé par un moteur déterministe. J'ai fait ce choix volontairement, car un modèle de langage peut par nature varier légèrement d'une exécution à l'autre sur une évaluation subjective comme la criticité, et faire reposer une décision automatisée à impact réel sur une sortie non déterministe aurait introduit un risque que je considère inacceptable dans un contexte de sécurité. Gemma2 reste donc un outil précieux d'aide à la décision et de rédaction du triage, tandis que l'arbitrage métier critique demeure entièrement piloté par la règle Wazuh.

---

## Slide 7 — TheHive crée le cas

Voici un cas réel créé automatiquement dans TheHive, dans lequel vous pouvez voir, directement dans la description, la sortie brute de Gemma2 telle qu'intégrée par le pipeline. Il ne s'agit pas d'un cas que j'aurais créé manuellement pour les besoins de la démonstration, puisqu'il a été généré par le compte de service du pipeline, ce qui apparaît d'ailleurs clairement dans le champ indiquant son créateur.

---

## Slide 8 — Preuve que l'automatisation est réelle

J'ai anticipé une question tout à fait légitime, à savoir comment prouver que ce cas provient bien du pipeline automatisé et non d'une manipulation manuelle de ma part pour la démonstration. Cette slide apporte précisément la réponse technique à cette interrogation, puisqu'il s'agit de la réponse HTTP brute renvoyée par TheHive au moment même de l'exécution du workflow Shuffle, avec le même identifiant de cas que celui affiché sur la capture précédente. La corrélation entre le journal d'exécution du workflow et le contenu réel du cas, associée au fait que le compte créateur soit un compte de service et non un compte humain, constitue à mon sens une preuve technique difficilement contestable de l'automatisation de bout en bout.

---

## Slide 9 — Cortex enrichit l'IOC

Voici maintenant l'historique réel des jobs d'enrichissement exécutés par Cortex, où chaque ligne correspond à une analyse réelle de l'indicateur de compromission extrait de l'alerte, en l'occurrence l'adresse IP suspecte, via l'analyzer AbuseIPDB qui interroge une base de réputation externe reconnue. L'ensemble des jobs affichés se sont conclus avec succès.

---

## Slide 10 — Rapport d'enrichissement détaillé

Voici à présent le détail d'un rapport Cortex réel, c'est-à-dire le résultat retourné par l'API AbuseIPDB sur l'adresse IP suspecte, avec des informations concrètes de réputation qui viennent objectiver et compléter le triage initial de Gemma2 grâce à une source de renseignement externe et indépendante.

---

## Slide 11 — MISP partage la menace

Lorsque la sévérité déterminée par le baseline Wazuh est élevée, le pipeline crée automatiquement un événement dans MISP, la plateforme de partage de renseignement sur la menace. Cet événement contient les éléments de contexte de l'alerte et permettrait, dans un contexte réel de production, de partager cet indicateur avec d'autres organisations ou d'autres instances de sécurité au sein d'un même groupe.

---

## Slide 12 — IOC réel extrait et corrélé

Voici l'indicateur de compromission concret intégré à cet événement MISP, à savoir l'adresse IP de destination, déjà corrélée automatiquement par la plateforme avec d'autres événements existants dans la base, ce qui illustre bien la valeur ajoutée de ce type d'outil, puisque plus les événements s'accumulent, plus la détection de campagnes récurrentes devient possible.

---

## Slide 13 — Notification finale

Nous arrivons à la dernière étape du pipeline, celle où une notification est envoyée pour informer qu'un traitement complet vient d'aboutir. J'ai d'ailleurs relié cette étape à une notification email réelle, que je vous montre ici, reçue sur ma propre boîte de réception au moment exact de l'exécution, ce qui referme la boucle entre la détection initiale et l'information effective de l'analyste.

---

## Slide 14 — Bilan

Pour conclure, je souhaite revenir sur la vision d'ensemble de ce projet plutôt que sur un détail technique isolé. Ce que j'ai construit ici, c'est une chaîne complète et cohérente qui reproduit, à l'échelle d'un laboratoire, le fonctionnement réel d'un centre opérationnel de sécurité moderne, en associant une détection fiable en amont grâce à Wazuh, un premier niveau de jugement automatisé grâce à l'intelligence artificielle, une gestion structurée des incidents avec TheHive, un enrichissement objectif par des sources externes avec Cortex, et un partage de renseignement avec MISP, le tout piloté de bout en bout par un moteur d'orchestration, sans intervention humaine entre la détection et la notification finale. La valeur ajoutée de ce travail ne réside donc pas simplement dans le fait d'avoir fait communiquer plusieurs outils entre eux, mais dans trois démonstrations précises que j'ai voulu mener avec rigueur : d'abord, que l'intelligence artificielle peut réellement accélérer et qualifier le travail d'un analyste SOC sans pour autant lui retirer la main sur les décisions critiques, ensuite, qu'un pipeline d'automatisation en sécurité doit être conçu pour échouer proprement plutôt que silencieusement, ce que j'ai vérifié en conditions réelles et non pas seulement en théorie, et enfin, que ce type d'architecture, même construite sur une infrastructure personnelle limitée, reste directement transposable à un environnement d'entreprise disposant de ressources plus importantes. Je conclus donc sur une conviction simple, à savoir que l'avenir des SOC ne repose pas sur le remplacement de l'analyste par l'intelligence artificielle, mais bien sur l'allègement de sa charge cognitive, afin qu'il puisse concentrer son expertise là où elle a le plus de valeur, c'est-à-dire l'investigation et la décision finale. C'est exactement cette logique que ce projet a cherché à démontrer de bout en bout, avec des preuves réelles et vérifiables, et c'est sur cette note que je souhaite terminer cette présentation. Je vous remercie pour votre attention, et je reste bien entendu à votre entière disposition pour toute question ou remarque.
