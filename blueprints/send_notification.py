import json
import azure.functions as func
from shared.config import CORREO_NOTIFICACIONES_TI
from shared.notifier import enviar_correo_html, construir_html_auditoria, construir_html_evento
from blueprints.get_full_audit import ejecutar_inventario_concurrente

bp_notification = func.Blueprint()

@bp_notification.route(route="send-notification", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def send_notification(req: func.HttpRequest) -> func.HttpResponse:
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

    recipient = str(body.get("recipientEmail") or body.get("email") or CORREO_NOTIFICACIONES_TI).strip()
    tipo_reporte = str(body.get("tipoReporte", "auditoria")).strip().lower()
    filtro = str(body.get("filter", "riesgo")).strip().lower()
    search_term = str(body.get("search", "")).strip().lower()
    detalle_evento = str(body.get("detalleEvento", "")).strip()

    if tipo_reporte not in {"auditoria", "creacion", "remediacion"}:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "tipoReporte debe ser auditoria, creacion o remediacion."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    if tipo_reporte == "creacion":
        html_body = construir_html_evento(
            titulo="NOTIFICACIÓN DE SOLICITUD DE AGENTE IA",
            color_acento="#238636",
            badge="GOBERNANZA DE CREACIÓN",
            detalles={
                "Solicitud / Agente": detalle_evento or search_term or "Agente Corporativo M365",
                "Estado": "Pendiente de validación",
                "Solicitante / Destinatario": recipient
            }
        )
        asunto = f"[GOBERNANZA IA] Notificación de Creación de Agente"
        resumen_registros = "Notificación de solicitud de agente"

    elif tipo_reporte == "remediacion":
        html_body = construir_html_evento(
            titulo="NOTIFICACIÓN DE REMEDIACIÓN / CUARENTENA DE AGENTE",
            color_acento="#da3633",
            badge="ALERTA SOC",
            detalles={
                "Agente / Identificador": detalle_evento or search_term or "Agente en Cuarentena",
                "Medida Aplicada": "Bloqueo preventivo y revocación de permisos Graph API",
                "Destinatario": recipient
            }
        )
        asunto = f"[REMEDIACIÓN SOC] Notificación de Contención de Agente"
        resumen_registros = "Acta de remediación SOC"

    else:
        auditoria = ejecutar_inventario_concurrente(filtro=filtro, search_term=search_term, limit=100)
        if "error" in auditoria:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": auditoria["error"]}, ensure_ascii=False),
                status_code=502,
                mimetype="application/json"
            )
        agentes = auditoria.get("agentes", [])
        metricas = auditoria.get("metricasAgentMap", {})
        metricas["coberturaPermisosAplicacion"] = "NO EVALUADOS (appRoleAssignments)"
        criterio = (f"BÚSQUEDA: {search_term}" if search_term else f"FILTRO: {filtro}").upper()
        html_body = construir_html_auditoria(agents_data=agentes, criterio=criterio, metricas=metricas)
        asunto = f"Reporte de Gobernanza IA ({criterio}) - {len(agentes)} registros"
        resumen_registros = f"{len(agentes)} registros ({criterio})"

    ok, msg_envio = enviar_correo_html(asunto=asunto, cuerpo_html=html_body, destinatario=recipient)
    if ok:
        respuesta_ejecutiva = (
            "NOTIFICACIÓN ENVIADA EXITOSAMENTE\n"
            "- ESTADO: SUCCESS\n"
            "- Firma digital: SIG_GOV_NOTIFY_OK\n"
            f"- Tipo de Reporte: {tipo_reporte.upper()}\n"
            f"- Destinatario: {recipient}\n"
            f"- Contenido: {resumen_registros}"
        )
        return func.HttpResponse(
            json.dumps({"status": "SUCCESS", "message": msg_envio, "respuestaEjecutiva": respuesta_ejecutiva}, ensure_ascii=False),
            status_code=200,
            mimetype="application/json"
        )

    return func.HttpResponse(
        json.dumps({"status": "ERROR", "message": msg_envio}, ensure_ascii=False),
        status_code=500,
        mimetype="application/json"
    )
