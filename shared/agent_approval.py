import base64
import binascii
import hashlib
import hmac
import json
import time

from shared.config import AGENT_APPROVAL_HMAC_SECRET, AGENT_APPROVER_EMAILS

MAX_APPROVAL_LIFETIME_SECONDS = 600


def _decode_base64url(value: str) -> bytes:
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise ValueError("Non-canonical base64url value")
    return decoded


def validar_aprobacion_operacion(
    token: str,
    action: str,
    target_id: str,
    details: str,
) -> tuple[bool, int, str]:
    if (
        len(AGENT_APPROVAL_HMAC_SECRET.encode("utf-8")) < 32
        or not AGENT_APPROVER_EMAILS
    ):
        return False, 503, "El despliegue está deshabilitado: falta configurar la firma y la lista de aprobadores."
    if not token or len(token) > 8192:
        return False, 403, "La aprobación firmada es inválida, expiró o no corresponde a esta solicitud."

    try:
        if token.count(".") != 1:
            raise ValueError("Invalid approval token format")
        payload_encoded, signature_encoded = token.split(".", 1)
        expected_signature = hmac.new(
            AGENT_APPROVAL_HMAC_SECRET.encode("utf-8"),
            payload_encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
        supplied_signature = _decode_base64url(signature_encoded)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise ValueError("Invalid approval signature")

        payload = json.loads(_decode_base64url(payload_encoded))
        if not isinstance(payload, dict):
            raise ValueError("Approval payload must be an object")
        now = int(time.time())
        issued_at = int(payload["issuedAt"])
        expires_at = int(payload["expiresAt"])
        approved_by = str(payload["approvedBy"]).strip().lower()
        details_hash = hashlib.sha256(details.encode("utf-8")).hexdigest()

        if (
            payload.get("action") != action
            or payload.get("targetId") != target_id
            or payload.get("detailsSha256") != details_hash
            or not str(payload.get("approvalId", "")).strip()
            or approved_by not in AGENT_APPROVER_EMAILS
            or issued_at > now
            or expires_at <= now
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_APPROVAL_LIFETIME_SECONDS
        ):
            raise ValueError("Approval claims are invalid")
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return False, 403, "La aprobación firmada es inválida, expiró o no corresponde a esta solicitud."

    return True, 200, "Aprobación verificada."
