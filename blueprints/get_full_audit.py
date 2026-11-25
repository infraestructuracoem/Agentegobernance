import json
import time
import csv
import os
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse
import azure.functions as func
from shared.config import UMBRAL_RIESGO_ALTO, PERMISOS_ALTO_IMPACTO
from shared.graph_client import get_graph_token, create_concurrent_session, normalizar_texto
from shared.enterprise_sources import (
    fetch_azure_ai_resources,
    fetch_defender_cloud_apps,
    map_azure_resource_to_inventory,
    map_defender_app_to_inventory,
)

bp_audit = func.Blueprint()

FRASES_GENERICAS_IGNORAR = {
    "all",
    "todos",
    "todas",
    "todo",
    "agentes en riesgo",
    "todos los agentes",
    "all agents",
    "all agents inventory",
    "lista de agentes",
    "auditoria",
    "auditoria de agentes",
    "auditoria general",
    "auditoria general de agentes",
    "auditoria total de agentes",
    "auditoria completa de agentes",
    "auditar agentes",
    "resumen de gobernanza",
    "auditoria global",
}
INDICIOS_IA = (
    "artificial intelligence", "inteligencia artificial", "machine learning",
    "azure openai", "openai", "chatgpt", "copilot", "generative ai",
    "generative", "generativa", "foundation model", "large language model",
    "llm", "gpt", "claude", "gemini", "vertex ai", "perplexity", "hugging face",
    "huggingface", "mistral", "deepseek", "cognitive services", "ai foundry",
    "azure machine learning", "ai agent", "ai-agent", "agente ia", "agente ai",
    "ai assistant", "ai-assistant",
)
INDICIOS_IA_DEBILES = ("agent", "agente", "assistant", "asistente", " chatbot", " bot")


def _marcar_clasificacion_ia(item: dict) -> dict:
    texto = normalizar_texto(" ".join(
        str(item.get(field, ""))
        for field in ("nombre", "plataforma", "descripcion", "tipoRecurso")
    ))
    coincidencias = [indicator for indicator in INDICIOS_IA if normalizar_texto(indicator) in texto]
    weak_matches = [indicator.strip() for indicator in INDICIOS_IA_DEBILES if indicator in f" {texto}"]
    item["esPosibleIA"] = bool(item.get("esPosibleIA") or coincidencias or weak_matches)
    item["indiciosIA"] = coincidencias
    item["confianzaDeteccion"] = (
        "ALTA" if coincidencias else ("BAJA (nombre o descripción)" if weak_matches else "SIN INDICIOS")
    )
    if weak_matches and not coincidencias:
        item["indiciosIA"] = weak_matches
    item["tipoInventario"] = item.get("tipoInventario", "APLICACION")
    return item

def _cargar_snapshot_defender() -> dict:
    ruta = os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared", "defender_snapshot.csv")
    snapshot = {}
    try:
        with open(ruta, "r", encoding="utf-8-sig", newline="") as archivo:
            for fila in csv.DictReader(archivo):
                nombre = normalizar_texto(fila.get("Nombre para mostrar", ""))
                if not nombre:
                    continue
                try:
                    score = int(fila.get("Puntuación de riesgo", ""))
                except (TypeError, ValueError):
                    continue
                snapshot[nombre] = max(snapshot.get(nombre, 0), max(0, min(score, 100)))
    except (OSError, csv.Error):
        return {}
    return snapshot

def _score_defender(nombre: str, snapshot: dict) -> int | None:
    return snapshot.get(normalizar_texto(nombre))


def _fetch_app_role_assignments(session, service_principals: list, start: float, max_time: float) -> tuple[dict, bool]:
    assignments_by_principal = {}
    pending = []
    complete = True
    for sp in service_principals:
        principal_id = str(sp.get("id", "")).strip()
        if principal_id:
            pending.append((principal_id, f"/servicePrincipals/{principal_id}/appRoleAssignments?$top=999"))
        else:
            complete = False

    def fetch_batch(batch):
        requests_body = [
            {"id": str(index), "method": "GET", "url": url}
            for index, (_, url) in enumerate(batch)
        ]
        try:
            response = session.post(
                "https://graph.microsoft.com/v1.0/$batch",
                json={"requests": requests_body},
                timeout=8,
            )
            if response.status_code != 200:
                return [(principal_id, [], None, False) for principal_id, _ in batch]
            response_by_id = {
                item.get("id"): item
                for item in response.json().get("responses", [])
                if isinstance(item, dict)
            }
            results = []
            for index, (principal_id, _) in enumerate(batch):
                item = response_by_id.get(str(index))
                if not item or item.get("status") != 200:
                    results.append((principal_id, [], None, False))
                    continue
                body = item.get("body")
                if not isinstance(body, dict):
                    results.append((principal_id, [], None, False))
                    continue
                assignments = body.get("value", [])
                if not isinstance(assignments, list):
                    results.append((principal_id, [], None, False))
                    continue
                next_link = body.get("@odata.nextLink")
                if next_link:
                    parsed = urlparse(next_link)
                    next_url = parsed.path
                    if next_url.startswith("/v1.0/"):
                        next_url = next_url[len("/v1.0"):]
                    if parsed.query:
                        next_url = f"{next_url}?{parsed.query}"
                else:
                    next_url = None
                results.append((principal_id, assignments, next_url, True))
            return results
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            return [(principal_id, [], None, False) for principal_id, _ in batch]

    while pending and time.time() - start < max_time:
        batches = [pending[index:index + 20] for index in range(0, len(pending), 20)]
        remaining_seconds = max_time - (time.time() - start)
        max_batches = max(1, int(max(0, remaining_seconds - 1) // 8) * 5)
        pending = [item for batch in batches[max_batches:] for item in batch]
        batches = batches[:max_batches]
        with ThreadPoolExecutor(max_workers=min(5, len(batches))) as executor:
            batch_results = list(executor.map(fetch_batch, batches))
        for results in batch_results:
            for principal_id, assignments, next_url, succeeded in results:
                assignments_by_principal.setdefault(principal_id, []).extend(assignments)
                complete = complete and succeeded
                if next_url:
                    pending.append((principal_id, next_url))
    if pending:
        complete = False
    return assignments_by_principal, complete


def ejecutar_inventario_concurrente(
    filtro: str = "all",
    search_term: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    start = time.time()
    max_time = 55.0
    limit = max(1, min(limit, 500))
    offset = max(0, min(offset, 50000))
    filtro = (filtro or "all").strip().lower()
    search_term = normalizar_texto(search_term or "")
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
        complete = True
        while url and pages < 45 and (time.time() - start) < max_time:
            try:
                response = session.get(url, timeout=timeout)
                if response.status_code != 200:
                    complete = False
                    break
                data = response.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                pages += 1
            except (requests.RequestException, ValueError, AttributeError):
                complete = False
                break
        if url:
            complete = False
        return items, complete

    with ThreadPoolExecutor(max_workers=4) as executor:
        catalog_future = executor.submit(
            fetch_items,
            "https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages",
        )
        service_principals_future = executor.submit(
            fetch_items,
            "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,displayName,description,appId,tags,accountEnabled,publisherName,verifiedPublisher,servicePrincipalType",
        )
        grants_future = executor.submit(fetch_items, "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999")
        applications_future = executor.submit(
            fetch_items,
            "https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,description,tags,publisherDomain,verifiedPublisher,signInAudience,createdDateTime,requiredResourceAccess",
        )
        catalog, catalog_completo = catalog_future.result()
        service_principals, sps_completos = service_principals_future.result()
        grants, grants_completos = grants_future.result()
        applications, applications_complete = applications_future.result()

    app_role_assignments, app_role_assignments_completos = _fetch_app_role_assignments(
        session, service_principals, start, max_time
    )
    if not (
        sps_completos and grants_completos
        and app_role_assignments_completos and applications_complete
    ):
        return {"error": "No se pudo completar el inventario de todas las fuentes Graph; no se generó un reporte parcial."}

    grants_map = {}
    for grant in grants:
        client_id = grant.get("clientId")
        if not client_id:
            continue
        entry = grants_map.setdefault(client_id, {"scopes": [], "consentType": grant.get("consentType", "Principal")})
        entry["scopes"].extend(grant.get("scope", "").split())
        if grant.get("consentType") == "AllPrincipals":
            entry["consentType"] = "AllPrincipals"

    service_principals_by_app_id = {
        str(sp.get("appId", "")).lower(): sp
        for sp in service_principals
        if sp.get("appId")
    }

    agentes = []
    agents_by_app_id = {}
    seen = set()
    for package in catalog:
        package_id = str(package.get("id", "")).strip()
        app_id = str(package.get("appId") or "").strip()
        if not package_id or package_id in seen:
            continue
        seen.update(value for value in (package_id, app_id) if value)
        name = str(package.get("displayName") or "Agente M365")
        state = str(package.get("state") or ("Blocked" if package.get("isBlocked") else "Active"))
        unowned = state.lower() in ["orphaned", "unowned"] or "sin propietario" in name.lower()
        related_sp = service_principals_by_app_id.get(app_id.lower())
        grant = grants_map.get(str(related_sp.get("id"))) if related_sp else None
        app_assignments = app_role_assignments.get(str(related_sp.get("id")), []) if related_sp else []
        scopes = " ".join(grant["scopes"]).lower() if grant else ""
        critical_permission = any(permission in scopes for permission in PERMISOS_ALTO_IMPACTO)
        score = 25
        if state.lower() in ["disabled", "blocked"] or (
            related_sp and not related_sp.get("accountEnabled", True)
        ):
            score += 20
        if unowned:
            score += 30
        if str(package.get("riskLevel", "")).lower() == "high":
            score += 40
        if grant:
            score += 15
            if critical_permission:
                score += 20
        if app_assignments:
            score += 20
        defender_score = _score_defender(name, snapshot_defender)
        if defender_score is not None:
            score = max(score, defender_score)
        score = min(score, 100)
        en_riesgo = score >= UMBRAL_RIESGO_ALTO
        publisher = str(
            package.get("publisherName")
            or package.get("publisher")
            or (related_sp or {}).get("publisherName")
            or "Microsoft 365"
        )
        verified_publisher = ((related_sp or {}).get("verifiedPublisher") or {}).get("displayName")
        enabled = (
            state.lower() not in ["disabled", "blocked"]
            and not package.get("isBlocked", False)
            and (related_sp.get("accountEnabled", True) if related_sp else True)
        )
        element_types = package.get("elementTypes")
        item = {
            "id": package_id,
            "appId": app_id,
            "nombre": name,
            "descripcion": str(
                package.get("shortDescription")
                or (related_sp or {}).get("description", "")
            ),
            "plataforma": str(package.get("platform") or publisher),
            "origen": "Microsoft 365 Agent 365 Package Management",
            "tipoPaquete": package.get("type"),
            "tiposElemento": element_types if isinstance(element_types, list) else [],
            "agentIdentityId": package.get("agentIdentityId"),
            "manifestId": package.get("manifestId"),
            "disponiblePara": package.get("availableTo"),
            "implementadoPara": package.get("deployedTo"),
            "version": package.get("version"),
            "enabled": bool(enabled),
            "sinPropietario": unowned,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": (
                "Sí (delegado y aplicación)" if grant and app_assignments
                else "Sí (delegado)" if grant
                else "Sí (aplicación)" if app_assignments
                else "No detectado" if related_sp
                else "No evaluado"
            ),
            "tipoPermiso": (
                "Delegado y aplicación" if grant and app_assignments
                else "Delegado" if grant
                else "Aplicación" if app_assignments
                else "No detectado" if related_sp
                else "No evaluado"
            ),
            "tipoConsentimiento": "Administrador" if (grant and grant["consentType"] == "AllPrincipals") else "Usuario",
            "editor": verified_publisher or publisher,
            "enRiesgo": en_riesgo,
            "tipoInventario": "AGENTE",
        }
        agentes.append(_marcar_clasificacion_ia(item))
        if app_id:
            agents_by_app_id[app_id.lower()] = item

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
        app_assignments = app_role_assignments.get(object_id, [])
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
        if app_assignments:
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
        item = {
            "id": object_id,
            "appId": app_id,
            "nombre": name,
            "descripcion": str(sp.get("description", "")),
            "plataforma": platform,
            "origen": "Interno" if "microsoft" in publisher_lower else "Externo",
            "enabled": enabled,
            "sinPropietario": unowned,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": (
                "Sí (delegado y aplicación)" if grant and app_assignments
                else "Sí (delegado)" if grant
                else "Sí (aplicación)" if app_assignments
                else "No detectado"
            ),
            "tipoPermiso": (
                "Delegado y aplicación" if grant and app_assignments
                else "Delegado" if grant
                else "Aplicación" if app_assignments
                else "No detectado"
            ),
            "tipoConsentimiento": "Administrador" if (grant and grant["consentType"] == "AllPrincipals") else "Usuario",
            "editor": verified or publisher or "N/D",
            "enRiesgo": en_riesgo,
            "tipoInventario": "APLICACION",
        }
        agentes.append(_marcar_clasificacion_ia(item))
        if app_id:
            agents_by_app_id[app_id.lower()] = item

    for application in applications:
        app_id = str(application.get("appId", "")).strip()
        object_id = str(application.get("id", "")).strip()
        if not app_id or not object_id:
            continue
        existing = agents_by_app_id.get(app_id.lower())
        if existing:
            existing["registroAplicacion"] = True
            existing["descripcion"] = str(application.get("description") or existing.get("descripcion", ""))
            existing["fechaCreacion"] = application.get("createdDateTime")
            existing["dominioPublicador"] = application.get("publisherDomain")
            _marcar_clasificacion_ia(existing)
            continue

        display_name = str(application.get("displayName") or "Aplicación de Entra ID")
        tags = application.get("tags") or []
        required_resources = application.get("requiredResourceAccess") or []
        permission_count = sum(
            len(resource.get("resourceAccess", []))
            for resource in required_resources
            if isinstance(resource, dict) and isinstance(resource.get("resourceAccess", []), list)
        )
        item = _marcar_clasificacion_ia({
            "id": object_id,
            "appId": app_id,
            "nombre": display_name,
            "descripcion": str(application.get("description") or ""),
            "plataforma": "Entra ID App Registration",
            "origen": "Microsoft Entra ID - App registrations",
            "tags": tags,
            "fechaCreacion": application.get("createdDateTime"),
            "dominioPublicador": application.get("publisherDomain"),
            "audienciaInicioSesion": application.get("signInAudience"),
            "permisosConfigurados": permission_count,
            "enabled": True,
            "sinPropietario": False,
            "puntuacionRiesgo": min(100, 25 + min(permission_count, 15) * 3),
            "nivelRiesgo": "PENDIENTE DE VALIDACIÓN",
            "accesoGraphAPI": "Permisos configurados; consentimiento efectivo se evalúa en el service principal",
            "tipoPermiso": "Configuración de app registration",
            "tipoConsentimiento": "No evaluado",
            "editor": str((application.get("verifiedPublisher") or {}).get("displayName") or application.get("publisherDomain") or "N/D"),
            "enRiesgo": permission_count >= 15,
            "tipoInventario": "APLICACION",
            "registroAplicacion": True,
        })
        agentes.append(item)
        agents_by_app_id[app_id.lower()] = item

    with ThreadPoolExecutor(max_workers=2) as executor:
        azure_future = executor.submit(fetch_azure_ai_resources, 18)
        defender_future = executor.submit(fetch_defender_cloud_apps, session)
        azure_resources, azure_status = azure_future.result()
        defender_apps, defender_status = defender_future.result()

    for resource in azure_resources:
        agentes.append(_marcar_clasificacion_ia(map_azure_resource_to_inventory(resource)))

    for cloud_app in defender_apps:
        agentes.append(_marcar_clasificacion_ia(map_defender_app_to_inventory(cloud_app)))

    inventario_completo = list(agentes)
    agentes.sort(key=lambda item: item["puntuacionRiesgo"], reverse=True)
    if search_term:
        agentes = [
            item for item in agentes
            if search_term in normalizar_texto(item["nombre"])
            or search_term in item["id"].lower()
            or search_term in str(item["appId"]).lower()
            or search_term in str(item.get("agentIdentityId", "")).lower()
            or search_term in str(item.get("manifestId", "")).lower()
            or search_term in normalizar_texto(item["plataforma"])
            or search_term in normalizar_texto(item.get("descripcion", ""))
            or search_term in normalizar_texto(item.get("origen", ""))
        ]
    if filtro in ["riesgo", "riesgosos", "criticos"]:
        agentes = [item for item in agentes if item["enRiesgo"]]
    elif filtro in ["no_administrados", "no-administrados"]:
        agentes = [item for item in agentes if item["plataforma"] in ["Terceros", "Otros"]]
    elif filtro in ["sin_propietario", "sin-propietario", "sin-propietarios"]:
        agentes = [item for item in agentes if item["sinPropietario"]]
    elif filtro in ["ia", "ai", "agentes_ia", "agentes-ia", "posibles_agentes_ia"]:
        agentes = [item for item in agentes if item["esPosibleIA"]]
    elif filtro in ["agentes", "agents", "agent365", "registro_agentes"]:
        agentes = [item for item in agentes if item["tipoInventario"] == "AGENTE"]
    elif filtro in ["azure_ai", "azure-ai", "ia_azure"]:
        agentes = [item for item in agentes if item["origen"] == "Azure Resource Graph"]
    elif filtro in ["defender", "cloud_apps", "cloud-apps"]:
        agentes = [item for item in agentes if item["origen"] == "Microsoft Defender XDR Advanced Hunting"]
    elif filtro in ["aplicaciones", "apps", "entra"]:
        agentes = [item for item in agentes if item["tipoInventario"] == "APLICACION"]
    elif filtro != "all":
        agentes = [item for item in agentes if filtro in item["plataforma"].lower()]

    source_status = {
        "agent365PackageManagement": {
            "estado": "COMPLETA" if catalog_completo else "PARCIAL",
            "registros": len(catalog),
            "detalle": "" if catalog_completo else (
                "Consulta incompleta; requiere Microsoft Agent 365 y el permiso "
                "CopilotPackages.Read.All."
            ),
        },
        "servicePrincipals": {"estado": "COMPLETA" if sps_completos else "PARCIAL", "registros": len(service_principals)},
        "oauth2PermissionGrants": {"estado": "COMPLETA" if grants_completos else "PARCIAL", "registros": len(grants)},
        "appRoleAssignments": {
            "estado": "COMPLETA" if app_role_assignments_completos else "PARCIAL",
            "registros": sum(len(items) for items in app_role_assignments.values()),
        },
        "appRegistrations": {"estado": "COMPLETA" if applications_complete else "PARCIAL", "registros": len(applications)},
        "azureResourceGraph": azure_status,
        "defenderXdr": defender_status,
        "purview": {
            "estado": "NO_CONSULTADO",
            "registros": 0,
            "detalle": (
                "Purview ofrece controles y señales de cumplimiento para agentes, "
                "pero no se consulta aquí como fuente de inventario."
            ),
        },
        "serviciosNoConsultados": ["Microsoft Purview"],
    }
    all_inventory_count = len(inventario_completo)
    all_possible_ai_count = sum(1 for item in inventario_completo if item["esPosibleIA"])
    all_risk_count = sum(1 for item in inventario_completo if item["enRiesgo"])
    all_application_count = sum(1 for item in inventario_completo if item["tipoInventario"] == "APLICACION")
    all_source_complete = all(
        status.get("estado") == "COMPLETA"
        for status in source_status.values()
        if isinstance(status, dict)
    )

    return {
        "agentes": agentes[offset:offset + limit],
        "fuentes": source_status,
        "estadoCobertura": "COMPLETA" if all_source_complete else "PARCIAL",
        "totalInventario": all_inventory_count,
        "tiempoRespuestaSegundos": round(time.time() - start, 2),
        "metricasGlobales": {
            "totalAplicaciones": all_application_count,
            "totalAgentesRegistrados": sum(
                1 for item in inventario_completo if item["tipoInventario"] == "AGENTE"
            ),
            "posiblesAgentesIA": all_possible_ai_count,
            "agentesEnRiesgo": all_risk_count,
            "recursosAzureIA": azure_status["registros"],
            "aplicacionesCloudObservadas": defender_status["registros"],
        },
        "totalFiltrados": len(agentes),
        "metricasAgentMap": {
            "totalAgentes": len(agentes),
            "totalAplicaciones": sum(1 for item in agentes if item["tipoInventario"] == "APLICACION"),
            "posiblesAgentesIA": sum(1 for item in agentes if item["esPosibleIA"]),
            "agentesSinPropietario": sum(1 for item in agentes if item["sinPropietario"]),
            "agentesEnRiesgo": sum(1 for item in agentes if item["enRiesgo"]),
            "agentesNoAdministrados": sum(1 for item in agentes if item["plataforma"] in ["Terceros", "Otros"]),
            "coberturaPermisosAplicacion": "COMPLETA",
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

@bp_audit.route(route="get-full-audit", auth_level=func.AuthLevel.FUNCTION, methods=["GET", "POST"])
def get_full_audit(req: func.HttpRequest) -> func.HttpResponse:
    start_time = time.time()
    MAX_TIME = 55.0

    filtro = str(req.params.get("filter", "")).strip().lower()
    search_term_raw = str(req.params.get("search", "")).strip()
    search_term = normalizar_texto(search_term_raw)
    try:
        limit = int(req.params.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 100))

    if req.method == "POST":
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
        filtro = str(body.get("filter", filtro)).strip().lower()
        search_term_raw = str(body.get("search", search_term_raw)).strip()
        search_term = normalizar_texto(search_term_raw)
        if "limit" in body and body["limit"] is not None:
            try:
                limit = int(body["limit"])
            except (TypeError, ValueError):
                return func.HttpResponse(
                    json.dumps({"status": "ERROR", "message": "El campo 'limit' debe ser un entero."}, ensure_ascii=False),
                    status_code=400,
                    mimetype="application/json"
                )

    if not filtro:
        filtro = "all"
    if search_term in FRASES_GENERICAS_IGNORAR:
        search_term = ""
        search_term_raw = ""
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
        completos = True
        catalog_base = "https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages"
        if search_term:
            nombre_odata = quote(search_term_raw.replace("'", "''"), safe="")
            catalog_base = (
                "https://graph.microsoft.com/beta/copilot/admin/catalog/packages"
                f"?$filter=contains(displayName,'{nombre_odata}')&$top=999"
            )
        url = catalog_base
        pages = 0
        while url and pages < 10 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    completos = False
                    break
                data = resp.json()
                for pkg in data.get("value", []):
                    items.append(pkg)
                url = data.get("@odata.nextLink")
                pages += 1
            except (requests.RequestException, ValueError, TypeError):
                completos = False
                break
        if url:
            completos = False
        return items, completos

    def fetch_service_principals():
        items = []
        completos = True
        sp_base = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            "?$top=100&$select=id,displayName,appId,tags,accountEnabled,publisherName,verifiedPublisher,servicePrincipalType"
        )
        if search_term:
            nombre_odata = quote(search_term_raw.replace("'", "''"), safe="")
            sp_base = (
                "https://graph.microsoft.com/v1.0/servicePrincipals"
                f"?$filter=contains(displayName,'{nombre_odata}')"
                "&$top=100&$select=id,displayName,appId,tags,accountEnabled,publisherName,verifiedPublisher,servicePrincipalType"
            )
        url = sp_base
        pages = 0
        while url and pages < 45 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    completos = False
                    break
                data = resp.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                pages += 1
            except (requests.RequestException, ValueError, TypeError):
                completos = False
                break
        if url:
            completos = False
        return items, completos

    def fetch_oauth_grants():
        grants_map = {}
        completos = True
        url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999"
        pages = 0
        while url and pages < 10 and (time.time() - start_time) < MAX_TIME:
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code != 200:
                    completos = False
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
            except (requests.RequestException, ValueError, TypeError):
                completos = False
                break
        if url:
            completos = False
        return grants_map, completos

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_cat = executor.submit(fetch_copilot_catalog)
        f_sp = executor.submit(fetch_service_principals)
        f_grants = executor.submit(fetch_oauth_grants)

        raw_catalog, catalog_completo = f_cat.result()
        raw_sps, sps_completo = f_sp.result()
        grants_map, grants_completos = f_grants.result()

    app_role_assignments, app_role_assignments_completos = _fetch_app_role_assignments(
        session, raw_sps, start_time, MAX_TIME
    )

    agentes_unificados = []
    ids_vistos = set()
    service_principals_by_app_id = {
        str(sp.get("appId", "")).lower(): sp
        for sp in raw_sps
        if sp.get("appId")
    }

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
        related_sp = service_principals_by_app_id.get(app_id.lower()) if app_id != "N/A" else None
        grant_info = grants_map.get(str(related_sp.get("id"))) if related_sp else None
        application_assignments = app_role_assignments.get(str(related_sp.get("id")), []) if related_sp else []
        scopes_str = " ".join(grant_info["scopes"]).lower() if grant_info else ""
        critical_permission = any(p in scopes_str for p in PERMISOS_ALTO_IMPACTO)

        score = 25
        if state == "Disabled" or (related_sp and not related_sp.get("accountEnabled", True)):
            score += 20
        if sin_prop:
            score += 30
        if str(pkg.get("riskLevel", "")).lower() == "high":
            score += 40
        if grant_info:
            score += 15
            if critical_permission:
                score += 20
        if application_assignments:
            score += 20
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
            "enabled": state != "Disabled" and (related_sp.get("accountEnabled", True) if related_sp else True),
            "sinPropietario": sin_prop,
            "puntuacionRiesgo": score,
            "nivelRiesgo": "ALTO" if en_riesgo else ("MEDIO" if score >= 50 else "BAJO"),
            "accesoGraphAPI": (
                "Sí (delegado y aplicación)" if grant_info and application_assignments
                else "Sí (delegado)" if grant_info
                else "Sí (aplicación)" if application_assignments
                else "No detectado" if related_sp
                else "No evaluado"
            ),
            "tipoPermiso": (
                "Delegado y aplicación" if grant_info and application_assignments
                else "Delegado" if grant_info
                else "Aplicación" if application_assignments
                else "No detectado" if related_sp
                else "No evaluado"
            ),
            "tipoConsentimiento": "Administrador" if (grant_info and grant_info["consentType"] == "AllPrincipals") else "Usuario",
            "editor": ((related_sp or {}).get("verifiedPublisher") or {}).get("displayName") or plat,
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
        application_assignments = app_role_assignments.get(obj_id, [])
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
        if application_assignments:
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
            "accesoGraphAPI": (
                "Sí (delegado y aplicación)" if tiene_grants and application_assignments
                else "Sí (delegado)" if tiene_grants
                else "Sí (aplicación)" if application_assignments
                else "No detectado"
            ),
            "tipoPermiso": (
                "Delegado y aplicación" if tiene_grants and application_assignments
                else "Delegado" if tiene_grants
                else "Aplicación" if application_assignments
                else "No detectado"
            ),
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
            if search_term in normalizar_texto(a["nombre"])
            or search_term in a["id"].lower()
            or search_term in str(a["appId"]).lower()
            or search_term in normalizar_texto(a["plataforma"])
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
    cobertura_fuentes = catalog_completo and sps_completo and grants_completos and app_role_assignments_completos
    permisos_aplicacion_evaluados = app_role_assignments_completos
    cobertura_completa = cobertura_fuentes and permisos_aplicacion_evaluados
    estado_cobertura = "COMPLETA" if cobertura_completa else "PARCIAL"

    def fmt_num(n: int) -> str:
        return f"{n:,}".replace(",", ".")

    if filtro == "all" and not search_term:
        respuesta_ejecutiva = (
            "ESTADO DE VALIDACIÓN\n"
            f"- ESTADO: {'COBERTURA COMPLETA' if cobertura_completa else 'PARCIAL - NO CONCLUIR LA AUDITORÍA'}\n"
            "- Este reporte no constituye una aprobación ni una firma digital.\n\n"
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
            "- Se identifican Service Principals asociados a Copilot Studio y Azure AI Foundry.\n\n"
            "COBERTURA DE FUENTES\n"
            f"- Catálogo Copilot: {'COMPLETA' if catalog_completo else 'PARCIAL'}.\n"
            f"- Service Principals: {'COMPLETA' if sps_completo else 'PARCIAL'}.\n"
            f"- OAuth2 Permission Grants: {'COMPLETA' if grants_completos else 'PARCIAL'}.\n\n"
            f"- Permisos de aplicación (appRoleAssignments): {'COMPLETA' if app_role_assignments_completos else 'PARCIAL'}.\n\n"
            "PERÍMETRO ANALIZADO\n"
            "- Catálogo de Copilot en Microsoft 365, service principals y permisos delegados de Entra ID.\n"
            "- Puntuación auxiliar desde snapshot local de Defender; no se consulta Defender ni Purview en vivo y no se verifica la antigüedad del snapshot.\n"
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
            f"- Cobertura: {estado_cobertura} (Catálogo Copilot: {'COMPLETA' if catalog_completo else 'PARCIAL'}; "
            f"Service Principals: {'COMPLETA' if sps_completo else 'PARCIAL'}; OAuth2 Permission Grants: {'COMPLETA' if grants_completos else 'PARCIAL'}; "
            f"permisos de aplicación: {'COMPLETA' if app_role_assignments_completos else 'PARCIAL'}).\n"
            "- Este reporte no constituye una aprobación ni una firma digital.\n\n"
            f"{listado_txt}"
        )

    payload_respuesta = {
        "respuestaEjecutiva": respuesta_ejecutiva,
        "perimetroGobernanza": "Catálogo Copilot, service principals y permisos delegados de Entra ID",
        "tiempoRespuestaSegundos": elapsed,
        "estadoCobertura": estado_cobertura,
        "coberturaPermisosAplicacion": "COMPLETA" if app_role_assignments_completos else "PARCIAL",
        "fuentes": {
            "catalogoCopilot": "COMPLETA" if catalog_completo else "PARCIAL",
            "servicePrincipals": "COMPLETA" if sps_completo else "PARCIAL",
            "oauth2PermissionGrants": "COMPLETA" if grants_completos else "PARCIAL",
            "appRoleAssignments": "COMPLETA" if app_role_assignments_completos else "PARCIAL",
            "snapshotDefender": "LOCAL; ACTUALIZACIÓN NO VERIFICADA",
            "purview": "NO CONSULTADO",
            "defenderEnVivo": "NO CONSULTADO"
        },
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
