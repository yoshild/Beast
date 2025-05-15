# Beast

Ce dépôt contient deux scripts Python utilisés dans le cadre d’un projet de cybersécurité pour simuler une attaque de type BEAST (Browser Exploit Against SSL/TLS) en interagissant avec un serveur vulnérable utilisant TLS 1.0. Ces scripts permettent :

    d'intercepter des requêtes HTTPS en forçant l’usage de TLS 1.0,

    de désactiver les vérifications SSL pour interagir avec un proxy type mitmproxy,

    d’automatiser une attaque par brute force sur un cookie de session.

📁 Fichiers inclus
script_tls10_request.py (premier script)
🔍 Description

Ce script permet d’envoyer une requête HTTPS via un proxy (comme mitmproxy) vers une URL cible, en forçant l’usage de TLS 1.0. Il sert à tester si le serveur est vulnérable à ce protocole obsolète.
🔧 Fonctionnalités

    Proxy configuré pour rediriger le trafic HTTP/HTTPS.

    Utilisation d’un adapter personnalisé (TLSv10Adapter) pour imposer TLS 1.0.

    Suppression des avertissements InsecureRequestWarning.

    Impression du statut HTTP, du contenu de la réponse, et des cookies reçus.

bruteforce_cookie_tls10.py (deuxième script)
🔍 Description

Ce script effectue une attaque par brute-force sur un cookie de session (par exemple, un token nommé token). Il utilise TLS 1.0 pour contourner certains mécanismes de sécurité basés sur les versions modernes de TLS.
🔧 Fonctionnalités

    Création d’un adapter SSL personnalisé (SSLAdapter) pour forcer l'utilisation de TLS 1.0.

    Envoi de requêtes avec des tentatives progressives de cookie (token=<essai>).

    Interprétation de la réponse HTTP pour détecter une correspondance valide (par exemple si la page contient "Welcome").

    Construction progressive du cookie caractère par caractère jusqu’à sa découverte complète.

🛠️ Prérequis

    Python 3.x

    Bibliothèques : requests, urllib3

    Un proxy tel que mitmproxy si tu veux observer/modifier le trafic réseau

    Un serveur de test vulnérable à TLS 1.0 sur https://37.187.103.134:8443/

# Fonctionnement
1. Créé le réseau avec le script `create-nework.sh`
2. Build tous les docker
3. Lancé dans l'ordre les docker stunnel-client, mitmproxy puis python-script
