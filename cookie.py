#!/usr/bin/env python3
# coding: utf-8

import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Configurer le proxy pour utiliser mitmproxy
proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

url = "https://37.187.103.134:8443/"

# Envoyer la requête via le proxy mitmproxy
response = requests.get(url, proxies=proxies, verify=False)  # Désactive la vérification du certificat

print("Statut HTTP:", response.status_code)
print("Contenu de la réponse:")
print(response.text)

class TLSv10Adapter(HTTPAdapter):
    """
    Adapter pour forcer TLS1.0 sur les connexions HTTPS.
    """
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        # Création d'un contexte SSL qui n'accepte QUE TLSv1.0
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # On désactive SSLv2 et SSLv3 pour la propreté
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        # On ignore la vérification du certificat (auto-signé)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        pool_kwargs['ssl_context'] = ctx
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

def main():
    url = "https://37.187.103.134:8443/"

    # 1) On désactive l'avertissement InsecureRequestWarning  
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # 2) On crée une session et on monte notre adapter TLSv1.0
    session = requests.Session()
    session.mount("https://", TLSv10Adapter())

    try:
        # 3) On envoie la requête
        resp = session.get(url, timeout=5, verify=False)
        print("Statut HTTP :", resp.status_code)
        print("Contenu de la réponse :")
        print(resp.text)
        
        # 4) Afficher les cookies reçus sous forme lisible
        if resp.cookies:
            print("Cookies reçus :")
            # Afficher les cookies de manière lisible
            for cookie in resp.cookies:
                print(f"{cookie.name}: {cookie.value}")

    except Exception as e:
        print("Erreur de connexion :", e)

if __name__ == "__main__":
    main()
