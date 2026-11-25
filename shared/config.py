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
ALLOWED_NOTIFICATION_DOMAINS = tuple(
    domain.strip().lower()
    for domain in os.environ.get("ALLOWED_NOTIFICATION_DOMAINS", "coem.co").split(",")
    if domain.strip()
)
AGENT_APPROVAL_HMAC_SECRET = os.environ.get("AGENT_APPROVAL_HMAC_SECRET", "")
AGENT_APPROVER_EMAILS = frozenset(
    email.strip().lower()
    for email in os.environ.get("AGENT_APPROVER_EMAILS", "").split(",")
    if email.strip()
)
AZURE_SUBSCRIPTION_IDS = tuple(
    value.strip()
    for value in os.environ.get("AZURE_SUBSCRIPTION_IDS", "").split(",")
    if value.strip()
)
AZURE_MANAGEMENT_GROUP_IDS = tuple(
    value.strip()
    for value in os.environ.get("AZURE_MANAGEMENT_GROUP_IDS", "").split(",")
    if value.strip()
)
try:
    DEFENDER_HUNTING_LOOKBACK_DAYS = max(
        1, min(int(os.environ.get("DEFENDER_HUNTING_LOOKBACK_DAYS", "30")), 30)
    )
except ValueError:
    DEFENDER_HUNTING_LOOKBACK_DAYS = 30

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
