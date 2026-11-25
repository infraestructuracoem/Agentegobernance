import json
import re
import requests
import azure.functions as func
from shared.config import PALABRAS_PROHIBIDAS, CORREO_NOTIFICACIONES_TI, FUNCTION_APP_NAME
from shared.graph_client import normalizar_texto, get_graph_token, create_concurrent_session
from shared.notifier import enviar_correo_html, construir_html_evento
from shared.agent_approval import validar_aprobacion_operacion

bp_create = func.Blueprint()

GUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

@bp_create.route(route="create-agent", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def create_agent(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Cuerpo JSON inválido."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    if not isinstance(body, dict):
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "El cuerpo debe ser un objeto JSON."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    solicitud_raw = str(body.get("solicitud", "")).strip()
    agent_object_id = str(body.get("agentObjectId", "")).strip()
    recipient_email = str(body.get("recipientEmail", CORREO_NOTIFICACIONES_TI)).strip()
    approval_token = str(body.get("approvalToken", "")).strip()

    if not solicitud_raw:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "El campo 'solicitud' es obligatorio."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    solicitud_norm = normalizar_texto(solicitud_raw)
    if any(p in solicitud_norm for p in PALABRAS_PROHIBIDAS):
        res_err = {
            "status": "REJECTED",
            "estadoFinal": "ESTADO = RECHAZADO",
            "respuestaEjecutiva": "ESTADO = RECHAZADO\nLa especificación del agente infringe las políticas corporativas de DLP/AUP."
        }
        return func.HttpResponse(json.dumps(res_err, ensure_ascii=False), status_code=400, mimetype="application/json")

    vinculacion_estado = "Pendiente de vincular y validar el agente en Entra ID y el catálogo de Copilot."
    if agent_object_id:
        if not GUID_PATTERN.fullmatch(agent_object_id):
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "agentObjectId debe ser un GUID válido."}, ensure_ascii=False),
                status_code=400,
                mimetype="application/json"
            )
        aprobado, status_code, mensaje_aprobacion = validar_aprobacion_operacion(
            approval_token,
            "deploy-agent",
            agent_object_id,
            solicitud_raw,
        )
        if not aprobado:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": mensaje_aprobacion}, ensure_ascii=False),
                status_code=status_code,
                mimetype="application/json"
            )
        token = get_graph_token()
        if not token:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "No se pudo autenticar con Microsoft Graph; no se realizó el despliegue."}, ensure_ascii=False),
                status_code=503,
                mimetype="application/json"
            )

        session = create_concurrent_session(token)
        url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{agent_object_id}"
        url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals/{agent_object_id}"
        package_data = {}
        package_activated = False
        sp_enable_attempted = False
        sp_initial_enabled = True

        def rollback_package() -> int | None:
            if not package_activated:
                return None
            try:
                rollback = session.patch(
                    url_pkg,
                    json={
                        "state": package_data.get("state", "Disabled"),
                        "isAvailableToEveryone": package_data.get("isAvailableToEveryone", False),
                    },
                    timeout=5,
                )
                return rollback.status_code
            except requests.RequestException:
                return None

        def rollback_service_principal() -> int | None:
            if not sp_enable_attempted or sp_initial_enabled:
                return None
            try:
                rollback = session.patch(url_sp, json={"accountEnabled": False}, timeout=5)
                return rollback.status_code
            except requests.RequestException:
                return None

        try:
            resp_pkg = session.get(url_pkg, timeout=5)
            resp_sp = session.get(url_sp, timeout=5)
            if resp_pkg.status_code != 200 or resp_sp.status_code != 200:
                return func.HttpResponse(
                    json.dumps({
                        "status": "ERROR",
                        "message": "No se pudo validar el agente tanto en el catálogo de Copilot como en Entra ID; no se realizó el despliegue.",
                        "catalogStatus": resp_pkg.status_code,
                        "entraStatus": resp_sp.status_code
                    }, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )

            package_data = resp_pkg.json()
            sp_initial_enabled = bool(resp_sp.json().get("accountEnabled", True))

            package_activated = True
            resp_pkg = session.patch(url_pkg, json={"state": "Active", "isAvailableToEveryone": True}, timeout=5)
            if resp_pkg.status_code not in [200, 204]:
                rollback_status = rollback_package()
                return func.HttpResponse(
                    json.dumps({
                        "status": "ERROR",
                        "message": "Falló la activación del paquete de Copilot; se intentó restaurar su estado anterior.",
                        "catalogStatus": resp_pkg.status_code,
                        "rollbackStatus": rollback_status
                    }, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )
            package_activated = True

            sp_enable_attempted = True
            resp_sp = session.patch(url_sp, json={"accountEnabled": True}, timeout=5)
            if resp_sp.status_code not in [200, 204]:
                rollback_status = rollback_package()
                sp_rollback_status = rollback_service_principal()
                return func.HttpResponse(
                    json.dumps({
                        "status": "ERROR",
                        "message": "Falló la actualización del service principal. Se intentó restaurar el estado anterior del paquete; verifica el resultado antes de reintentar.",
                        "catalogStatus": resp_pkg.status_code,
                        "entraStatus": resp_sp.status_code,
                        "rollbackStatus": rollback_status,
                        "servicePrincipalRollbackStatus": sp_rollback_status
                    }, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )
            vinculacion_estado = f"Desplegado globalmente en Entra ID y catálogo de Copilot (ID: {agent_object_id})"
        except (requests.RequestException, ValueError):
            rollback_status = rollback_package()
            sp_rollback_status = rollback_service_principal()
            return func.HttpResponse(
                json.dumps({
                    "status": "ERROR",
                    "message": "Error al procesar Microsoft Graph; se intentó restaurar el estado anterior del paquete si ya se había activado.",
                    "rollbackStatus": rollback_status,
                    "servicePrincipalRollbackStatus": sp_rollback_status
                }, ensure_ascii=False),
                status_code=502,
                mimetype="application/json"
            )

    instrucciones = (
        f"1. ROL PRINCIPAL: Asistente especializado en {solicitud_raw}.\n"
        "2. CONTROLES DLP: Prohibido exponer credenciales, tokens, PII o evadir filtros de seguridad.\n"
        f"3. SOPORTE Y ESCALAMIENTO: Reportar incidentes a {CORREO_NOTIFICACIONES_TI}."
    )

    html_acta = construir_html_evento(
        titulo="ACTA DE PREAPROBACIÓN DE AGENTE IA" if not agent_object_id else "ACTA DE APROBACIÓN Y DESPLIEGUE GLOBAL DE AGENTE IA",
        color_acento="#238636",
        badge="PREAPROBACIÓN PENDIENTE" if not agent_object_id else "APROBADO GLOBAL",
        detalles={
            "Objetivo del Agente": solicitud_raw,
            "Object ID Vinculado": agent_object_id or "Pre-aprobación sin ID asignado",
            "Estado Entra ID / M365": vinculacion_estado,
            "Controles DLP": "Lista heurística sin coincidencias; no sustituye una revisión de seguridad",
            "Infraestructura": FUNCTION_APP_NAME
        }
    )
    enviado, msg_correo = enviar_correo_html(
        asunto=(
            f"[GOBERNANZA IA] {'Agente desplegado' if agent_object_id else 'Solicitud de agente'}: "
            f"{solicitud_raw[:50]}"
        ),
        cuerpo_html=html_acta,
        destinatario=recipient_email
    )

    respuesta_ejecutiva = (
        "DICTAMEN DE CREACIÓN Y DESPLIEGUE DE AGENTE\n"
        f"- ESTADO: {'PREAPROBACIÓN (PENDIENTE DE VALIDACIÓN EN ENTRA ID)' if not agent_object_id else 'APROBADO Y DESPLEGADO'}\n"
        f"- Aprobación: {'pendiente de validación' if not agent_object_id else 'token HMAC validado'}\n"
        f"- Descripción recibida: {solicitud_raw}\n"
        f"- Estado Entra ID / M365: {vinculacion_estado}\n"
        f"- Notificación por Correo: {msg_correo}\n\n"
        "INSTRUCCIONES DE SEGURIDAD ASIGNADAS:\n"
        f"{instrucciones}"
    )

    reporte = {
        "status": "PREAPPROVED" if not agent_object_id else "APPROVED",
        "estadoFinal": "ESTADO = PREAPROBACIÓN PENDIENTE DE VINCULACIÓN" if not agent_object_id else "ESTADO = APROBADO Y DESPLEGADO",
        "objetivoDelAgente": solicitud_raw,
        "requisitosEntraID": vinculacion_estado,
        "notificacionEnviada": enviado,
        "instruccionesAgente": instrucciones,
        "respuestaEjecutiva": respuesta_ejecutiva
    }
    return func.HttpResponse(json.dumps(reporte, ensure_ascii=False), status_code=200, mimetype="application/json")
