https://www.root-me.org/fr/Challenges/Reseau/SIP-Authentification?debut_repository_recherche=0&lang=fr

Le challenge porte sur l'analyse d'un fichier de capture réseau utilisant le protocole SIP.

L'objectif de ce challenge est de retrouver le mot de passe utilisé pour s’authentifier sur l’infrastructure SIP.

Dans un premier temps on a télécharger le fichier qui était donné dans le challenge. Voici le contenu du fichier : 
172.25.105.3"172.25.105.40"555"asterisk"REGISTER"sip:172.25.105.40"4787f7ce""""PLAIN"1234
172.25.105.3"172.25.105.40"555"asterisk"INVITE"sip:1000@172.25.105.40"70fbfdae""""MD5"aa533f6efa2b2abac675c1ee6cbde327
172.25.105.3"172.25.105.40"555"asterisk"BYE"sip:1000@172.25.105.40"70fbfdae""""MD5"0b306e9db1f819dd824acf3227b60e07

Sachant que l’authentification SIP utilise l’authentification digest MD5 dont le processus est:  
    1. La requête initiale : Le client envoie une requête comme REGISTER pour s'enregistrer ou INVITE pour passer un appel sans informations d'authentification. 
    2. Le défi : Le serveur rejette la demande avec un code 401 Unauthorized (ou 407 Proxy Authentication Required). Dans ce message, il envoie une valeur aléatoire unique appelée un Nonce (Number used once) et le nom du domaine (Realm). 
    3. La réponse calculée : Le client prend son mot de passe, le combine avec le Nonce, le Realm, la méthode SIP et l'URI, puis passe le tout dans une fonction de hachage. Il renvoie la requête initiale, mais cette fois en y incluant ce condensé (Response). 
    4. La vérification : Le serveur, qui connaît aussi le mot de passe du client, fait le même calcul de son côté. Si les résultats correspondent, il valide l'accès avec un code 200 OK. 

En analysant le contenu du fichier texte extrait de la capture réseau, nous avons vu que ces trois lignes distinctes correspondent à différentes phases d'une session SIP (Enregistrement, Appel, Fin d'appel). Chaque ligne suit une structure de champs précise. Isolons les éléments de la deuxième ligne (INVITE) pour comprendre la mécanique du défi MD5 : 
    ● IP Source (Client) : 172.25.105.3 
    ● IP Destination (Serveur SIP) : 172.25.105.40 
    ● Identifiant / Extension : 555 
    ● Realm (Domaine) : asterisk 
    ● Méthode SIP : INVITE 
    ● URI de destination : sip:1000@172.25.105.40 
    ● Nonce (Défi du serveur) : 70fbfdae 
    ● Type d'authentification : MD5 
    ● Response (Hash réseau) : aa533f6efa2b2abac675c1ee6cbde327 

Normalement, face à un hash d'authentification Digest MD5 (aa533f6efa2b2abac675c1ee6cbde327), la méthodologie standard impose une attaque par dictionnaire en ligne de commande (via des outils comme Hashcat avec le mode 11400 ou John the Ripper). 

Cependant, l'examen de la première ligne (REGISTER) met en évidence une vulnérabilité critique de configuration de l'infrastructure : le stockage ou la transmission de mots de passe en clair. 

L'analyse de cette ligne révèle : 
    ● Méthode : REGISTER 
    ● Type d'authentification : PLAIN (Indique que le protocole n'a appliqué aucun hachage/chiffrement lors de cette transaction). 
    ● Valeur finale : 1234 

D'où le mot de passe chercher est : '1234'