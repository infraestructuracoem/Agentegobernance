import json
import re
import requests
import azure.functions as func
from shared.config import PALABRAS_PROHIBIDAS, CORREO_NOTIFICACIONES_TI, FUNCTION_APP_NAME
from shared.graph_client import normalizar_texto, get_graph_token, create_concurrent_session
from shared.notifier import enviar_correo_html, construir_html_evento

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

            resp_pkg = session.patch(url_pkg, json={"state": "Active", "isAvailableToEveryone": True}, timeout=5)
            if resp_pkg.status_code not in [200, 204]:
                return func.HttpResponse(
                    json.dumps({
                        "status": "ERROR",
                        "message": "Falló la activación del paquete de Copilot; el despliegue no se completó.",
                        "catalogStatus": resp_pkg.status_code
                    }, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )

            resp_sp = session.patch(url_sp, json={"appRoleAssignmentRequired": False, "accountEnabled": True}, timeout=5)
            if resp_sp.status_code not in [200, 204]:
                return func.HttpResponse(
                    json.dumps({
                        "status": "ERROR",
                        "message": "El paquete de Copilot se activó, pero falló la actualización del service principal. Requiere revisión manual.",
                        "catalogStatus": resp_pkg.status_code,
                        "entraStatus": resp_sp.status_code
                    }, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )
            vinculacion_estado = f"Desplegado globalmente en Entra ID y catálogo de Copilot (ID: {agent_object_id})"
        except requests.RequestException:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "Error de red con Microsoft Graph; no se pudo completar el despliegue."}, ensure_ascii=False),
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
            "Controles DLP": "Activos (Sin infracciones detectadas)",
            "Infraestructura": FUNCTION_APP_NAME
        }
    )
    enviado, msg_correo = enviar_correo_html(
        asunto=f"[GOBERNANZA IA] Agente Aprobado: {solicitud_raw[:50]}",
        cuerpo_html=html_acta,
        destinatario=recipient_email
    )

    respuesta_ejecutiva = (
        "DICTAMEN DE CREACIÓN Y DESPLIEGUE DE AGENTE\n"
        f"- ESTADO: {'PREAPROBACIÓN (PENDIENTE DE VALIDACIÓN EN ENTRA ID)' if not agent_object_id else 'APROBADO Y DESPLEGADO'}\n"
        f"- Firma de Gobernanza: {'SIG_GOV_PREAPPROVAL_PENDING' if not agent_object_id else 'SIG_GOV_APPROVED_OK'}\n"
        f"- Objetivo Validado: {solicitud_raw}\n"
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
