import json
from concurrent.futures import ThreadPoolExecutor
import azure.functions as func
from shared.config import CORREO_NOTIFICACIONES_TI
from shared.graph_client import get_graph_token, create_concurrent_session
from shared.notifier import enviar_correo_html, construir_html_evento

bp_remediation = func.Blueprint()

@bp_remediation.route(route="execute-remediation", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def execute_remediation(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Cuerpo JSON inválido."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    bot_id = str(body.get("botId", "")).strip()
    search_query = str(body.get("searchQuery", "")).strip().lower()
    tipo_accion = str(body.get("tipoAccion", "SoftDelete")).strip()
    recipient_email = str(body.get("recipientEmail", CORREO_NOTIFICACIONES_TI)).strip()

    if not bot_id and not search_query:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Debes proporcionar 'botId' o 'searchQuery'."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    token = get_graph_token()
    if not token:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "No se pudo autenticar con Microsoft Graph API."}, ensure_ascii=False),
            status_code=500,
            mimetype="application/json"
        )

    session = create_concurrent_session(token)
    sp_object_id = None
    sp_name = None

    if bot_id:
        url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=id eq '{bot_id}' or appId eq '{bot_id}'&$select=id,displayName,appId"
        resp = session.get(url_sp, timeout=5)
        if resp.status_code == 200:
            vals = resp.json().get("value", [])
            if vals:
                sp_object_id = vals[0]["id"]
                sp_name = vals[0].get("displayName")

    if not sp_object_id and search_query:
        url_sp = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,displayName,appId"
        resp = session.get(url_sp, timeout=6)
        if resp.status_code == 200:
            for item in resp.json().get("value", []):
                if (
                    search_query in str(item.get("displayName", "")).lower()
                    or search_query in str(item.get("id", "")).lower()
                    or search_query in str(item.get("appId", "")).lower()
                ):
                    sp_object_id = item["id"]
                    sp_name = item.get("displayName")
                    break

    if not sp_object_id:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": f"Agente no encontrado en Entra ID: '{bot_id or search_query}'."}, ensure_ascii=False),
            status_code=404,
            mimetype="application/json"
        )

    grants_revocados = 0
    url_grants = f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '{sp_object_id}'"
    resp_grants = session.get(url_grants, timeout=5)
    if resp_grants.status_code == 200:
        grants = resp_grants.json().get("value", [])
        if grants:
            def _delete_grant(gid: str):
                session.delete(f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{gid}", timeout=5)

            with ThreadPoolExecutor(max_workers=5) as ex:
                ex.map(_delete_grant, [g["id"] for g in grants if g.get("id")])
            grants_revocados = len(grants)

    es_borrado_total = tipo_accion.lower() in ["harddelete", "delete", "eliminar"]
    url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{sp_object_id}"
    url_sp_target = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}"

    if es_borrado_total:
        session.delete(url_pkg, timeout=5)
        resp_action = session.delete(url_sp_target, timeout=5)
        accion_txt = "ELIMINADO DEFINITIVAMENTE"
    else:
        session.patch(url_pkg, json={"state": "Disabled"}, timeout=5)
        resp_action = session.patch(url_sp_target, json={"accountEnabled": False}, timeout=5)
        accion_txt = "PUESTO EN CUARENTENA (accountEnabled = False)"

    if resp_action.status_code in [200, 204]:
        html_soc = construir_html_evento(
            titulo="REPORTE DE REMEDIACIÓN Y CONTENCIÓN SOC EN ENTRA ID",
            color_acento="#da3633",
            badge="REMEDIACIÓN SOC",
            detalles={
                "Agente Intervenido": sp_name,
                "Object ID": sp_object_id,
                "Medida Aplicada": accion_txt,
                "Tipo de Operación": tipo_accion,
                "Concesiones OAuth2 Revocadas": grants_revocados
            }
        )
        enviado, msg_correo = enviar_correo_html(
            asunto=f"[REMEDIACIÓN SOC] Agente Intervenido: {sp_name}",
            cuerpo_html=html_soc,
            destinatario=recipient_email
        )

        msg = f"El agente '{sp_name}' (ID: {sp_object_id}) fue {accion_txt}. Permisos OAuth2 revocados: {grants_revocados}."
        respuesta_ejecutiva = (
            "REMEDIACIÓN SOC EJECUTADA\n"
            "- ESTADO: SUCCESS\n"
            "- Firma: SIG_GOV_REMEDIATION_OK\n"
            f"- Agente: {sp_name}\n"
            f"- Object ID: {sp_object_id}\n"
            f"- Acción Aplicada: {accion_txt}\n"
            f"- Concesiones Graph API Revocadas: {grants_revocados}\n"
            f"- Notificación SOC: {msg_correo}"
        )
        return func.HttpResponse(
            json.dumps({
                "status": "SUCCESS",
                "message": msg,
                "notificacionEnviada": enviado,
                "respuestaEjecutiva": respuesta_ejecutiva
            }, ensure_ascii=False),
            status_code=200,
            mimetype="application/json"
        )

    return func.HttpResponse(
        json.dumps({"status": "ERROR", "message": f"Error Graph API ({resp_action.status_code}): {resp_action.text}"}, ensure_ascii=False),
        status_code=resp_action.status_code,
        mimetype="application/json"
    )
