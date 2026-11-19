import json
import re
from concurrent.futures import ThreadPoolExecutor
import requests
import azure.functions as func
from shared.config import CORREO_NOTIFICACIONES_TI
from shared.graph_client import get_graph_token, create_concurrent_session
from shared.notifier import enviar_correo_html, construir_html_evento

bp_remediation = func.Blueprint()
GUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

@bp_remediation.route(route="execute-remediation", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def execute_remediation(req: func.HttpRequest) -> func.HttpResponse:
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

    bot_id = str(body.get("botId", "")).strip()
    search_query = str(body.get("searchQuery", "")).strip()
    tipo_accion = str(body.get("tipoAccion", "SoftDelete")).strip()
    recipient_email = str(body.get("recipientEmail", CORREO_NOTIFICACIONES_TI)).strip()

    tipo_accion_normalizada = tipo_accion.lower()
    if tipo_accion_normalizada not in ["softdelete", "harddelete"]:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "tipoAccion debe ser SoftDelete o HardDelete."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    es_borrado_total = tipo_accion_normalizada == "harddelete"
    if es_borrado_total and body.get("confirmHardDelete") is not True:
        return func.HttpResponse(
            json.dumps({
                "status": "ERROR",
                "message": "HardDelete requiere confirmación explícita mediante confirmHardDelete=true."
            }, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    if bot_id and search_query:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Proporciona botId o searchQuery, pero no ambos."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )
    if not bot_id and not search_query:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Debes proporcionar 'botId' o 'searchQuery'."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )
    if bot_id and not GUID_PATTERN.fullmatch(bot_id):
        search_query = bot_id
        bot_id = ""
    if len(search_query) > 200:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "searchQuery excede el límite permitido de 200 caracteres."}, ensure_ascii=False),
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
    identifier = bot_id or search_query
    if GUID_PATTERN.fullmatch(identifier):
        filter_clause = f"id eq '{identifier}' or appId eq '{identifier}'"
    else:
        identifier_literal = identifier.replace("'", "''")
        filter_clause = f"displayName eq '{identifier_literal}'"

    try:
        url_sp = "https://graph.microsoft.com/v1.0/servicePrincipals"
        params = {
            "$filter": filter_clause,
            "$select": "id,displayName,appId"
        }
        matches = []
        while url_sp and len(matches) < 2:
            resp = session.get(url_sp, params=params, timeout=6)
            params = None
            if resp.status_code != 200:
                return func.HttpResponse(
                    json.dumps({"status": "ERROR", "message": f"No se pudo resolver el agente en Entra ID (HTTP {resp.status_code})."}, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )
            page = resp.json()
            matches.extend(page.get("value", []))
            url_sp = page.get("@odata.nextLink")
        if len(matches) > 1:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "El identificador coincide con varios agentes. Usa el Object ID exacto."}, ensure_ascii=False),
                status_code=409,
                mimetype="application/json"
            )
        sp_object_id = matches[0]["id"] if matches else None
        sp_name = matches[0].get("displayName") if matches else None
    except (requests.RequestException, ValueError, KeyError) as ex:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": f"Error al consultar Microsoft Graph: {str(ex)}"}, ensure_ascii=False),
            status_code=502,
            mimetype="application/json"
        )

    if not sp_object_id:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": f"Agente no encontrado en Entra ID: '{bot_id or search_query}'."}, ensure_ascii=False),
            status_code=404,
            mimetype="application/json"
        )

    grants = []
    url_grants = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
    params = {"$filter": f"clientId eq '{sp_object_id}'"}
    try:
        while url_grants:
            resp_grants = session.get(url_grants, params=params, timeout=5)
            params = None
            if resp_grants.status_code != 200:
                return func.HttpResponse(
                    json.dumps({"status": "ERROR", "message": f"No se pudieron consultar todas las concesiones OAuth2 (HTTP {resp_grants.status_code}); no se realizó la remediación."}, ensure_ascii=False),
                    status_code=502,
                    mimetype="application/json"
                )
            data = resp_grants.json()
            grants.extend(data.get("value", []))
            url_grants = data.get("@odata.nextLink")
    except (requests.RequestException, ValueError) as ex:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": f"Error al consultar concesiones OAuth2: {str(ex)}; no se realizó la remediación."}, ensure_ascii=False),
            status_code=502,
            mimetype="application/json"
        )

    def _delete_grant(gid: str) -> tuple[str, int | None]:
        try:
            response = session.delete(
                f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{gid}",
                timeout=5
            )
            return gid, response.status_code
        except requests.RequestException:
            return gid, None

    grant_ids = [str(grant["id"]) for grant in grants if grant.get("id")]
    with ThreadPoolExecutor(max_workers=5) as executor:
        grant_results = list(executor.map(_delete_grant, grant_ids))
    grants_revocados = sum(1 for _, status in grant_results if status in [200, 204])
    grants_fallidos = len(grant_results) - grants_revocados

    url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{sp_object_id}"
    url_sp_target = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}"

    try:
        if es_borrado_total:
            resp_pkg = session.delete(url_pkg, timeout=5)
            resp_action = session.delete(url_sp_target, timeout=5)
            accion_txt = "ELIMINADO DEFINITIVAMENTE"
        else:
            resp_pkg = session.patch(url_pkg, json={"state": "Disabled"}, timeout=5)
            resp_action = session.patch(url_sp_target, json={"accountEnabled": False}, timeout=5)
            accion_txt = "PUESTO EN CUARENTENA (accountEnabled = False)"
    except requests.RequestException as ex:
        return func.HttpResponse(
            json.dumps({
                "status": "PARTIAL",
                "message": f"Error de red durante la remediación; concesiones revocadas: {grants_revocados}, fallidas: {grants_fallidos}. Se requiere verificación manual.",
                "error": str(ex)
            }, ensure_ascii=False),
            status_code=502,
            mimetype="application/json"
        )

    catalog_ok = resp_pkg.status_code in [200, 202, 204, 404]
    principal_ok = resp_action.status_code in [200, 202, 204]
    if not catalog_ok or not principal_ok or grants_fallidos:
        return func.HttpResponse(
            json.dumps({
                "status": "PARTIAL",
                "message": "La remediación no se completó en todos los recursos; requiere verificación manual.",
                "servicePrincipalStatus": resp_action.status_code,
                "catalogStatus": resp_pkg.status_code,
                "catalogPackageFound": resp_pkg.status_code != 404,
                "grantsRevocados": grants_revocados,
                "grantsFallidos": grants_fallidos
            }, ensure_ascii=False),
            status_code=502,
            mimetype="application/json"
        )

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
        f"- Catálogo de Copilot: {'Actualizado' if resp_pkg.status_code != 404 else 'Sin paquete asociado'}\n"
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
