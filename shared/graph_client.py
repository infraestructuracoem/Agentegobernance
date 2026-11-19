import time
import unicodedata
import requests
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from shared.config import TENANT_ID, CLIENT_ID, CLIENT_SECRET

_TOKEN_CACHE = {"access_token": "", "expires_at": 0.0}
_TOKEN_LOCK = threading.Lock()

def normalizar_texto(texto: str) -> str:
    if not texto:
        return ""
    texto_norm = unicodedata.normalize("NFD", str(texto))
    return "".join(c for c in texto_norm if unicodedata.category(c) != "Mn").lower().strip()

def get_graph_token() -> str:
    now = time.time()
    if _TOKEN_CACHE["access_token"] and now < (_TOKEN_CACHE["expires_at"] - 120):
        return _TOKEN_CACHE["access_token"]
    if not TENANT_ID or not CLIENT_ID or not CLIENT_SECRET:
        return ""

    with _TOKEN_LOCK:
        now = time.time()
        if _TOKEN_CACHE["access_token"] and now < (_TOKEN_CACHE["expires_at"] - 120):
            return _TOKEN_CACHE["access_token"]
        url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default"
        }
        try:
            resp = requests.post(url, data=payload, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                expires_in = int(data.get("expires_in", 3599))
                if not token:
                    return ""
                _TOKEN_CACHE["access_token"] = token
                _TOKEN_CACHE["expires_at"] = now + expires_in
                return token
        except requests.RequestException:
            return ""
    return ""

def create_concurrent_session(token: str) -> requests.Session:
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=15, pool_maxsize=30, max_retries=retries)
    session.mount("https://", adapter)
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "ConsistencyLevel": "eventual"
    })
    return session
