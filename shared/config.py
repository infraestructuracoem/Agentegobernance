import os

FUNCTION_APP_NAME = os.environ.get("FUNCTION_APP_NAME", "func-gobernanza-core-v")
CORREO_REMITENTE_TI = os.environ.get("CORREO_REMITENTE_TI", "bcruzn@coem.co")
CORREO_NOTIFICACIONES_TI = os.environ.get("CORREO_NOTIFICACIONES_TI", "infraestructura@coem.co")
try:
    UMBRAL_RIESGO_ALTO = int(os.environ.get("UMBRAL_RIESGO_ALTO", "70"))
except ValueError:
    UMBRAL_RIESGO_ALTO = 70

TENANT_ID = os.environ.get("TENANT_ID") or os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_SECRET", "")

PALABRAS_PROHIBIDAS = [
    "ignore previous instructions", "bypass", "jailbreak", "prompt injection", "system prompt",
    "password", "passwords", "contrasena", "contrasenas", "credencial", "credenciales",
    "secret", "token", "api_key", "clave", "claves", "pin", "llave", "login",
    "drop table", "exploit", "malware", "pirata", "torrent", "hack",
    "tarjeta", "pii", "sensible", "confidencial", "ilegal", "secreto",
    "streaming no autorizado", "apuestas", "juegos"
]

PERMISOS_ALTO_IMPACTO = (
    "mail.", "files.", "directory.", "sites.", "user.readwrite",
    "rolemanagement", "application.readwrite", "appRoleAssignment"
)
