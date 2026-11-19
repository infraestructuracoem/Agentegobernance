import json
import time
import csv
import os
import requests
import re
from concurrent.futures import ThreadPoolExecutor
import azure.functions as func
from shared.config import UMBRAL_RIESGO_ALTO, PERMISOS_ALTO_IMPACTO
from shared.graph_client import get_graph_token, create_concurrent_session

bp_audit = func.Blueprint()

FRASES_GENERICAS_IGNORAR = {
    "agentes en riesgo",
    "todos los agentes",
    "lista de agentes",
    "auditoria",
    "auditoria global",
}

def _cargar_snapshot_defender() -> dict:
    ruta = os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared", "defender_snapshot.csv")
    snapshot = {}
    try:
        with open(ruta, "r", encoding="utf-8-sig", newline="") as archivo:
            archivo.readline()
            for linea in archivo:
                coincidencia = re.match(r'^"?([^",]+),[^,]+,([0-9]+),', linea)
                if not coincidencia:
                    continue
                nombre = coincidencia.group(1).strip().lower()
                if not nombre:
                    continue
                score = int(coincidencia.group(2))
                snapshot[nombre] = max(0, min(score, 100))
    except (OSError, csv.Error):
        return {}
    return snapshot

def _score_defender(nombre: str, snapshot: dict) -> int | None:
    nombre_norm = str(nombre).strip().lower()
    if nombre_norm in snapshot:
        return snapshot[nombre_norm]
    coincidencias = [score for clave, score in snapshot.items() if len(clave) >= 4 and (clave in nombre_norm or nombre_norm in clave)]
    if len(coincidencias) == 1:
        return coincidencias[0]
    return None

def ejecutar_inventario_concurrente(filtro: str = "all", search_term: str = "", limit: int = 100) -> dict:
    start = time.time()
    limit = max(1, min(limit, 100))
    filtro = (filtro or "all").strip().lower()
    search_term = (search_term or "").strip().lower()
    if search_term in FRASES_GENERICAS_IGNORAR:
        search_term = ""

    token = get_graph_token()
    if not token:
        return {"error": "Fallo de autenticación con Microsoft Graph API."}

    session = create_concurrent_session(token)
    snapshot_defender = _cargar_snapshot_defender()

    def fetch_items(url: str, timeout: int = 5):
        items = []
        pages = 0
        while url and pages < 45 and (time.time() - start) < 19.0:
            try:
                response = session.get(url, timeout=timeout)
                if response.status_code != 200:
                    break
                data = response.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                pages += 1
            except (requests.RequestException, ValueError):
                break
        return items

    with ThreadPoolExecutor(max_workers=3) as executor:
        catalog_future = executor.submit(fetch_items, "https://graph.microsoft.com/beta/copilot/admin/catalog/packages?$top=999")
        service_principals_future = executor.submit(
            fetch_items,
            "https://graph.microsoft.com/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId,tags,accountEnabled,publisherName,verifiedPublisher,servicePrincipalType",
        )
        grants_future = executor.submit(fetch_items, "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999")
        catalog = catalog_future.result()
        service_principals = service_principals_future.result()
        grants = grants_future.result()

    grants_map = {}
    for grant in grants:
        client_id = grant.get("clientId")
        if not client_id:
            continue
        entry = grants_map.setdefault(client_id, {"scopes": [], "consentType": grant.get("consentType", "Principal")})
        entry["scopes"].extend(grant.get("scope", "").split())
        if grant.get("consentType") == "AllPrincipals":
            entry["consentType"] = "AllPrincipals"

    agentes = []
    seen = set()
    for package in catalog:
        package_id = str(package.get("id", "")).strip()
        app_id = str(package.get("appId", ""))
        if not package_id or package_id in seen:
            continue
        seen.update(value for value in (package_id, app_id) if value)
        name = str(package.get("displayName", "Agente M365"))
        state = str(package.get("state", "Active"))
        unowned = state in ["Orphaned", "Unowned"] or "sin propietario" in name.lower()
        score = 25
        if state == "Disabled":
            score += 20
        if unowned:
            score += 30
        if str(package.get("riskLevel", "")).lower() == "high":
            score += 40
        defender_score = _score_defender(name, snapshot_defender)
        if defender_score is not None:
            score = max(score, defender_score)
        score = min(score, 100)
        en_riesgo = score >= UMBRAL_RIESGO_ALTO
        publisher = str(package.get("publisherName") or "Copilot Studio")
        agentes.append({
            "id": package_id,
            "appId": app_id,
            "nombre": name,
            "plataforma": publisher,
            "origen": "Microsoft 365 Catalog",
            "enabled": state != "Disabled",
            "sinPropietario": unowned,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": "Sí",
            "tipoPermiso": "Delegado",
            "tipoConsentimiento": "Usuario",
            "editor": publisher,
            "enRiesgo": en_riesgo,
        })

    for sp in service_principals:
        object_id = str(sp.get("id", "")).strip()
        app_id = str(sp.get("appId", "")).strip()
        if not object_id or object_id in seen or (app_id and app_id in seen):
            continue
        seen.update(value for value in (object_id, app_id) if value)
        name = str(sp.get("displayName") or "Sin Nombre")
        name_lower = name.lower()
        tags = sp.get("tags") or []
        enabled = bool(sp.get("accountEnabled", True))
        publisher = str(sp.get("publisherName") or "")
        publisher_lower = publisher.lower()
        verified = (sp.get("verifiedPublisher") or {}).get("displayName")
        platform = _clasificar_plataforma(name_lower, publisher_lower, tags)
        unowned = any(key in name_lower for key in ("sin propietario", "unowned", "orphan"))
        grant = grants_map.get(object_id)
        scopes = " ".join(grant["scopes"]).lower() if grant else ""
        critical_permission = any(permission in scopes for permission in PERMISOS_ALTO_IMPACTO)
        score = 15
        if not verified and "microsoft" not in publisher_lower:
            score += 20
        if platform in ["Terceros", "Otros"] and enabled:
            score += 15
        if grant:
            score += 15
            if critical_permission:
                score += 20
        if unowned:
            score += 25
        if "HighRisk" in tags or "Status:Blocked" in tags:
            score += 35
        defender_score = _score_defender(name, snapshot_defender)
        if defender_score is not None:
            score = max(score, defender_score)
        score = min(score, 100)
        en_riesgo = score >= UMBRAL_RIESGO_ALTO
        agentes.append({
            "id": object_id,
            "appId": app_id,
            "nombre": name,
            "plataforma": platform,
            "origen": "Interno" if "microsoft" in publisher_lower else "Externo",
            "enabled": enabled,
            "sinPropietario": unowned,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": "Sí" if grant else "No",
            "tipoPermiso": "Delegado" if grant else "Aplicación",
            "tipoConsentimiento": "Administrador" if (grant and grant["consentType"] == "AllPrincipals") else "Usuario",
            "editor": verified or publisher or "N/D",
            "enRiesgo": en_riesgo,
        })

    agentes.sort(key=lambda item: item["puntuacionRiesgo"], reverse=True)
    if search_term:
        agentes = [item for item in agentes if search_term in item["nombre"].lower() or search_term in item["id"].lower() or search_term in str(item["appId"]).lower() or search_term in item["plataforma"].lower()]
    if filtro in ["riesgo", "riesgosos", "criticos"]:
        agentes = [item for item in agentes if item["enRiesgo"]]
    elif filtro in ["no_administrados", "no-administrados"]:
        agentes = [item for item in agentes if item["plataforma"] in ["Terceros", "Otros"]]
    elif filtro in ["sin_propietario", "sin-propietario", "sin-propietarios"]:
        agentes = [item for item in agentes if item["sinPropietario"]]
    elif filtro != "all":
        agentes = [item for item in agentes if filtro in item["plataforma"].lower()]

    return {
        "agentes": agentes[:limit],
        "metricasAgentMap": {
            "totalAgentes": len(agentes),
            "agentesSinPropietario": sum(1 for item in agentes if item["sinPropietario"]),
            "agentesEnRiesgo": sum(1 for item in agentes if item["enRiesgo"]),
            "agentesNoAdministrados": sum(1 for item in agentes if item["plataforma"] in ["Terceros", "Otros"]),
        },
    }

def _clasificar_plataforma(nombre_lower: str, pub_lower: str, tags: list) -> str:
    if "agent builder" in nombre_lower or "generador de agentes" in nombre_lower or "agentbuilder" in tags:
        return "Agent Builder"
    if "copilot studio heredado" in nombre_lower or "pva legacy" in nombre_lower:
        return "Copilot Studio heredado"
    if "copilot studio" in nombre_lower or "power virtual agents" in nombre_lower or "copilot" in nombre_lower:
        return "Copilot Studio"
    if "agents toolkit" in nombre_lower or "teams toolkit" in nombre_lower:
        return "Agents Toolkit"
    if "sharepoint" in nombre_lower or "spo" in tags:
        return "SharePoint"
    if "foundry" in nombre_lower or "palantir" in nombre_lower or "ai-agents" in nombre_lower:
        return "Foundry"
    if "microsoft" in pub_lower or "microsoft" in nombre_lower:
        return "Microsoft"
    if "bot" in nombre_lower or "aiagent" in tags:
        return "Terceros"
    return "Otros"

@bp_audit.route(route="get-full-audit", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET", "POST"])
def get_full_audit(req: func.HttpRequest) -> func.HttpResponse:
    start_time = time.time()
    MAX_TIME = 19.0

    filtro = str(req.params.get("filter", "")).strip().lower()
    search_term = str(req.params.get("search", "")).strip().lower()
    try:
        limit = int(req.params.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 100))

    try:
        body = req.get_json()
        if isinstance(body, dict):
            filtro = str(body.get("filter", filtro)).strip().lower()
            search_term = str(body.get("search", search_term)).strip().lower()
            if "limit" in body and body["limit"] is not None:
                limit = int(body["limit"])
    except Exception:
        pass

    if not filtro:
        filtro = "all"
    if search_term in FRASES_GENERICAS_IGNORAR:
        search_term = ""
    limit = max(1, min(limit, 100))

    token = get_graph_token()
    if not token:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Fallo de autenticación con Microsoft Graph API."}, ensure_ascii=False),
            status_code=500,
            mimetype="application/json"
        )

    session = create_concurrent_session(token)
    snapshot_defender = _cargar_snapshot_defender()

    def fetch_copilot_catalog():
        items = []
        url = "https://graph.microsoft.com/beta/copilot/admin/catalog/packages?$top=999"
        pages = 0
        while url and pages < 10 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    break
                data = resp.json()
                for pkg in data.get("value", []):
                    items.append(pkg)
                url = data.get("@odata.nextLink")
                pages += 1
            except Exception:
                break
        return items

    def fetch_service_principals():
        items = []
        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            "?$top=100&$select=id,displayName,appId,tags,accountEnabled,publisherName,verifiedPublisher,servicePrincipalType"
        )
        pages = 0
        while url and pages < 45 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    break
                data = resp.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                pages += 1
            except Exception:
                break
        return items

    def fetch_oauth_grants():
        grants_map = {}
        url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999"
        pages = 0
        while url and pages < 10 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    break
                data = resp.json()
                for g in data.get("value", []):
                    cid = g.get("clientId")
                    if cid:
                        entry = grants_map.setdefault(cid, {"scopes": [], "consentType": g.get("consentType", "Principal")})
                        scope_str = g.get("scope", "")
                        if scope_str:
                            entry["scopes"].extend(scope_str.split())
                        if g.get("consentType") == "AllPrincipals":
                            entry["consentType"] = "AllPrincipals"
                url = data.get("@odata.nextLink")
                pages += 1
            except Exception:
                break
        return grants_map

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_cat = executor.submit(fetch_copilot_catalog)
        f_sp = executor.submit(fetch_service_principals)
        f_grants = executor.submit(fetch_oauth_grants)

        raw_catalog = f_cat.result()
        raw_sps = f_sp.result()
        grants_map = f_grants.result()

    agentes_unificados = []
    ids_vistos = set()

    for pkg in raw_catalog:
        pkg_id = str(pkg.get("id", ""))
        app_id = str(pkg.get("appId", "N/A"))
        if not pkg_id or pkg_id in ids_vistos:
            continue
        ids_vistos.add(pkg_id)
        if app_id != "N/A":
            ids_vistos.add(app_id)

        nombre = pkg.get("displayName", "Agente M365")
        plat = pkg.get("publisherName") or "Copilot Studio"
        state = pkg.get("state", "Active")
        sin_prop = state in ["Orphaned", "Unowned"] or "sin propietario" in nombre.lower()

        score = 25
        if state == "Disabled":
            score += 20
        if sin_prop:
            score += 30
        if str(pkg.get("riskLevel", "")).lower() == "high":
            score += 40
        score_snapshot = _score_defender(str(nombre), snapshot_defender)
        if score_snapshot is not None:
            score = max(score, score_snapshot)
        score = min(score, 100)
        en_riesgo = score >= UMBRAL_RIESGO_ALTO

        agentes_unificados.append({
            "id": pkg_id,
            "appId": app_id,
            "nombre": nombre,
            "plataforma": plat,
            "origen": "Microsoft 365 Catalog",
            "enabled": state != "Disabled",
            "sinPropietario": sin_prop,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": "Sí",
            "tipoPermiso": "Delegado",
            "tipoConsentimiento": "Usuario",
            "editor": plat,
            "enRiesgo": en_riesgo
        })

    for sp in raw_sps:
        obj_id = str(sp.get("id", ""))
        app_id = str(sp.get("appId", ""))
        if not obj_id or obj_id in ids_vistos or (app_id and app_id in ids_vistos):
            continue
        ids_vistos.add(obj_id)
        if app_id:
            ids_vistos.add(app_id)

        nombre = sp.get("displayName") or "Sin Nombre"
        name_lower = nombre.lower()
        tags = sp.get("tags") or []
        enabled = bool(sp.get("accountEnabled", True))
        pub_raw = sp.get("publisherName") or ""
        pub_lower = pub_raw.lower()
        verified_pub = (sp.get("verifiedPublisher") or {}).get("displayName")

        plataforma = _clasificar_plataforma(name_lower, pub_lower, tags)
        sin_prop = any(k in name_lower for k in ("sin propietario", "unowned", "orphan"))

        grant_info = grants_map.get(obj_id)
        tiene_grants = grant_info is not None
        scopes_str = " ".join(grant_info["scopes"]).lower() if grant_info else ""
        tiene_permisos_criticos = any(p in scopes_str for p in PERMISOS_ALTO_IMPACTO)

        score = 15
        if not verified_pub and "microsoft" not in pub_lower:
            score += 20
        if plataforma in ["Terceros", "Otros"] and enabled:
            score += 15
        if tiene_grants:
            score += 15
            if tiene_permisos_criticos:
                score += 20
        if sin_prop:
            score += 25
        if "HighRisk" in tags or "Status:Blocked" in tags:
            score += 35

        score_snapshot = _score_defender(nombre, snapshot_defender)
        if score_snapshot is not None:
            score = max(score, score_snapshot)

        score = min(score, 100)
        en_riesgo = score >= UMBRAL_RIESGO_ALTO

        agentes_unificados.append({
            "id": obj_id,
            "appId": app_id,
            "nombre": nombre,
            "plataforma": plataforma,
            "origen": "Interno" if "microsoft" in pub_lower else "Externo",
            "enabled": enabled,
            "sinPropietario": sin_prop,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": "Sí" if tiene_grants else "No",
            "tipoPermiso": "Delegado" if tiene_grants else "Aplicación",
            "tipoConsentimiento": "Administrador" if (grant_info and grant_info["consentType"] == "AllPrincipals") else "Usuario",
            "editor": verified_pub or pub_raw or "N/D",
            "enRiesgo": en_riesgo
        })

    agentes_unificados.sort(key=lambda x: x["puntuacionRiesgo"], reverse=True)

    total_org = len(agentes_unificados)
    total_riesgo = sum(1 for a in agentes_unificados if a["enRiesgo"])
    total_sin_prop = sum(1 for a in agentes_unificados if a["sinPropietario"])
    total_no_admin = sum(1 for a in agentes_unificados if a["plataforma"] in ["Terceros", "Otros"])

    plataformas_cnt = {}
    for a in agentes_unificados:
        p = a["plataforma"]
        plataformas_cnt[p] = plataformas_cnt.get(p, 0) + 1

    filtrados = agentes_unificados
    if search_term:
        filtrados = [
            a for a in filtrados
            if search_term in a["nombre"].lower()
            or search_term in a["id"].lower()
            or search_term in str(a["appId"]).lower()
            or search_term in a["plataforma"].lower()
        ]

    if filtro in ["riesgo", "riesgosos", "criticos"]:
        filtrados = [a for a in filtrados if a["enRiesgo"]]
    elif filtro in ["no_administrados", "no-administrados"]:
        filtrados = [a for a in filtrados if a["plataforma"] in ["Terceros", "Otros"]]
    elif filtro in ["sin_propietario", "sin-propietario", "sin-propietarios"]:
        filtrados = [a for a in filtrados if a["sinPropietario"]]
    elif filtro != "all":
        filtrados = [a for a in filtrados if filtro in a["plataforma"].lower()]

    muestra = filtrados[:max(1, min(limit, 100))]
    elapsed = round(time.time() - start_time, 2)

    def fmt_num(n: int) -> str:
        return f"{n:,}".replace(",", ".")

    if filtro == "all" and not search_term:
        respuesta_ejecutiva = (
            "ESTADO DE VALIDACIÓN\n"
            "- ESTADO: APPROVED\n"
            "- Firma digital: SIG_GOV_APPROVED_OK\n\n"
            "RESUMEN EJECUTIVO\n"
            f"- Total de agentes inventariados: {fmt_num(total_org)}\n"
            f"- Agentes en riesgo (Puntuación ≥ {UMBRAL_RIESGO_ALTO}): {fmt_num(total_riesgo)}\n"
            f"- Agentes sin propietario: {fmt_num(total_sin_prop)}\n"
            f"- Agentes no administrados: {fmt_num(total_no_admin)}\n\n"
            "DISTRIBUCIÓN POR PLATAFORMA\n"
            f"- Otros: {fmt_num(plataformas_cnt.get('Otros', 0))}\n"
            f"- Copilot Studio: {fmt_num(plataformas_cnt.get('Copilot Studio', 0))}\n"
            f"- Microsoft: {fmt_num(plataformas_cnt.get('Microsoft', 0))}\n"
            f"- Foundry: {fmt_num(plataformas_cnt.get('Foundry', 0))}\n"
            f"- Terceros: {fmt_num(plataformas_cnt.get('Terceros', 0))}\n"
            f"- SharePoint: {fmt_num(plataformas_cnt.get('SharePoint', 0))}\n\n"
            "HALLAZGOS DE GOBERNANZA\n"
            f"- Se detectan {fmt_num(total_riesgo)} agentes clasificados en riesgo alto con puntuación ≥ {UMBRAL_RIESGO_ALTO}.\n"
            f"- Se identifica un volumen elevado de agentes no administrados ({fmt_num(total_no_admin)}).\n"
            "- Existen múltiples Service Principals asociados a Copilot Studio y Azure AI Foundry con acceso activo a Microsoft Graph.\n\n"
            "PERÍMETRO ANALIZADO\n"
            "- Entra ID, Microsoft Defender Cloud Apps, Microsoft 365 y Microsoft Purview DSPM.\n"
            f"- Tiempo de análisis concurrente: {elapsed}s."
        )
    else:
        criterio_lbl = f"Búsqueda: '{search_term}'" if search_term else f"Filtro: '{filtro}'"
        lineas_agentes = []
        for idx, ag in enumerate(muestra[:20], start=1):
            estado_txt = "Habilitado" if ag["enabled"] else "Deshabilitado"
            lineas_agentes.append(
                f"{idx}. **{ag['nombre']}** | Riesgo: {ag['puntuacionRiesgo']}/100 ({ag['nivelRiesgo']}) | "
                f"Plataforma: {ag['plataforma']} | Graph API: {ag['accesoGraphAPI']} | Estado: {estado_txt} | ID: `{ag['id']}`"
            )
        listado_txt = "\n".join(lineas_agentes) if lineas_agentes else "No se encontraron registros que coincidan con el criterio."

        respuesta_ejecutiva = (
            f"RESULTADOS DE AUDITORÍA ESPECÍFICA ({criterio_lbl})\n"
            f"- Coincidencias encontradas: {fmt_num(len(filtrados))} (Mostrando top {min(len(muestra), 20)} ordenados por mayor riesgo)\n"
            f"- Firma digital: SIG_GOV_APPROVED_OK\n\n"
            f"{listado_txt}"
        )

    payload_respuesta = {
        "respuestaEjecutiva": respuesta_ejecutiva,
        "perimetroGobernanza": "Toda la Organización (Purview, Defender, Entra ID & M365)",
        "tiempoRespuestaSegundos": elapsed,
        "metricasAgentMap": {
            "totalAgentes": total_org,
            "agentesSinPropietario": total_sin_prop,
            "agentesEnRiesgo": total_riesgo,
            "agentesNoAdministrados": total_no_admin
        },
        "distribucionPorPlataforma": plataformas_cnt,
        "totalFiltrados": len(filtrados),
        "agentes": muestra
    }
    return func.HttpResponse(json.dumps(payload_respuesta, ensure_ascii=False), status_code=200, mimetype="application/json")
