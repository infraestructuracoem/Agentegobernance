import json
import azure.functions as func
from shared.config import PALABRAS_PROHIBIDAS, CORREO_NOTIFICACIONES_TI, FUNCTION_APP_NAME
from shared.graph_client import normalizar_texto, get_graph_token, create_concurrent_session
from shared.notifier import enviar_correo_html, construir_html_evento

bp_create = func.Blueprint()

@bp_create.route(route="create-agent", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def create_agent(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Cuerpo JSON inválido."}, ensure_ascii=False),
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

    vinculacion_estado = "Aprobado en catálogo de gobernanza (pendiente de vinculación de Object ID)"
    if agent_object_id:
        token = get_graph_token()
        if token:
            session = create_concurrent_session(token)
            try:
                url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{agent_object_id}"
                session.patch(url_pkg, json={"state": "Active", "isAvailableToEveryone": True}, timeout=5)

                url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals/{agent_object_id}"
                resp_sp = session.patch(url_sp, json={"appRoleAssignmentRequired": False, "accountEnabled": True}, timeout=5)
                if resp_sp.status_code in [200, 204]:
                    vinculacion_estado = f"Desplegado globalmente en Entra ID (ID: {agent_object_id})"
                else:
                    vinculacion_estado = f"Validado con observación en Entra ID (HTTP {resp_sp.status_code})"
            except Exception as ex:
                vinculacion_estado = f"Aprobado con error de red en Graph: {str(ex)}"

    instrucciones = (
        f"1. ROL PRINCIPAL: Asistente especializado en {solicitud_raw}.\n"
        "2. CONTROLES DLP: Prohibido exponer credenciales, tokens, PII o evadir filtros de seguridad.\n"
        f"3. SOPORTE Y ESCALAMIENTO: Reportar incidentes a {CORREO_NOTIFICACIONES_TI}."
    )

    html_acta = construir_html_evento(
        titulo="ACTA DE APROBACIÓN Y DESPLIEGUE GLOBAL DE AGENTE IA",
        color_acento="#238636",
        badge="APROBADO GLOBAL",
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
        "- ESTADO: APROBADO GLOBAL\n"
        "- Firma de Gobernanza: SIG_GOV_APPROVED_OK\n"
        f"- Objetivo Validado: {solicitud_raw}\n"
        f"- Estado Entra ID / M365: {vinculacion_estado}\n"
        f"- Notificación por Correo: {msg_correo}\n\n"
        "INSTRUCCIONES DE SEGURIDAD ASIGNADAS:\n"
        f"{instrucciones}"
    )

    reporte = {
        "status": "APPROVED",
        "estadoFinal": "ESTADO = APROBADO GLOBAL",
        "objetivoDelAgente": solicitud_raw,
        "requisitosEntraID": vinculacion_estado,
        "notificacionEnviada": enviado,
        "instruccionesAgente": instrucciones,
        "respuestaEjecutiva": respuesta_ejecutiva
    }
    return func.HttpResponse(json.dumps(reporte, ensure_ascii=False), status_code=200, mimetype="application/json")
