import time

import requests

from shared.config import (
    AZURE_MANAGEMENT_GROUP_IDS,
    AZURE_SUBSCRIPTION_IDS,
    DEFENDER_HUNTING_LOOKBACK_DAYS,
)
from shared.graph_client import create_concurrent_session, get_scoped_token

RESOURCE_GRAPH_API_VERSION = "2024-04-01"
RESOURCE_GRAPH_QUERY = """
Resources
| where type in~ (
    'microsoft.cognitiveservices/accounts',
    'microsoft.cognitiveservices/accounts/projects',
    'microsoft.machinelearningservices/workspaces',
    'microsoft.machinelearningservices/workspaces/onlineendpoints',
    'microsoft.machinelearningservices/workspaces/connections',
    'microsoft.botservice/botservices'
)
| project id, name, type, subscriptionId, resourceGroup, location, kind, tags
| order by id asc
"""


def fetch_azure_ai_resources(timeout_seconds: float = 25.0) -> tuple[list[dict], dict]:
    if not AZURE_SUBSCRIPTION_IDS and not AZURE_MANAGEMENT_GROUP_IDS:
        return [], {
            "estado": "NO_CONFIGURADO",
            "registros": 0,
            "detalle": "Configura AZURE_SUBSCRIPTION_IDS o AZURE_MANAGEMENT_GROUP_IDS.",
        }

    token = get_scoped_token("https://management.azure.com/.default")
    if not token:
        return [], {
            "estado": "ERROR",
            "registros": 0,
            "detalle": "No se pudo obtener un token de Azure Resource Manager.",
        }

    session = create_concurrent_session(token)
    url = (
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
        f"?api-version={RESOURCE_GRAPH_API_VERSION}"
    )
    scope = {}
    if AZURE_SUBSCRIPTION_IDS:
        scope["subscriptions"] = list(AZURE_SUBSCRIPTION_IDS)
    else:
        scope["managementGroups"] = list(AZURE_MANAGEMENT_GROUP_IDS)

    results = []
    start = time.monotonic()
    complete = True
    error_detail = ""
    try:
        while url and time.monotonic() - start < timeout_seconds:
            request_options = scope.get("options", {"$top": 1000, "resultFormat": "objectArray"})
            response = session.post(
                url,
                json={
                    "query": RESOURCE_GRAPH_QUERY,
                    **{key: value for key, value in scope.items() if key != "options"},
                    "options": request_options,
                },
                timeout=8,
            )
            if response.status_code != 200:
                complete = False
                return results, {
                    "estado": "PARCIAL" if results else "ERROR",
                    "registros": len(results),
                    "detalle": f"Azure Resource Graph respondió HTTP {response.status_code}.",
                }

            data = response.json()
            page = data.get("data", [])
            if not isinstance(page, list):
                complete = False
                break
            results.extend(page)

            skip_token = data.get("$skipToken")
            if data.get("resultTruncated") and not skip_token:
                complete = False
                error_detail = "Azure Resource Graph truncó resultados sin proporcionar un token de continuación."
            if skip_token:
                url = (
                    "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
                    f"?api-version={RESOURCE_GRAPH_API_VERSION}"
                )
                scope = {
                    "options": {
                        "$top": 1000,
                        "resultFormat": "objectArray",
                        "$skipToken": skip_token,
                    }
                }
                if AZURE_SUBSCRIPTION_IDS:
                    scope["subscriptions"] = list(AZURE_SUBSCRIPTION_IDS)
                else:
                    scope["managementGroups"] = list(AZURE_MANAGEMENT_GROUP_IDS)
            else:
                url = None

            if len(results) >= 5000 and url:
                complete = False
                break
    except (requests.RequestException, ValueError, TypeError, AttributeError) as ex:
        complete = False
        error_detail = str(ex)[:300]

    if url:
        complete = False
    return results, {
        "estado": "COMPLETA" if complete else ("PARCIAL" if results else "ERROR"),
        "registros": len(results),
        "detalle": "" if complete else (
            error_detail or "La consulta Azure Resource Graph quedó incompleta o alcanzó el límite de tiempo/resultados."
        ),
    }


def map_azure_resource_to_inventory(resource: dict) -> dict:
    resource_id = str(resource.get("id", "")).strip()
    name = str(resource.get("name") or resource_id.rsplit("/", 1)[-1] or "Azure AI resource")
    resource_type = str(resource.get("type", "")).lower()
    type_labels = {
        "microsoft.cognitiveservices/accounts": "Azure AI Services / Azure OpenAI",
        "microsoft.cognitiveservices/accounts/projects": "Azure AI Foundry project",
        "microsoft.machinelearningservices/workspaces": "Azure Machine Learning / AI Foundry",
        "microsoft.machinelearningservices/workspaces/onlineendpoints": "Azure ML online endpoint",
        "microsoft.machinelearningservices/workspaces/connections": "Azure AI connection",
        "microsoft.botservice/botservices": "Azure Bot Service",
    }
    return {
        "id": resource_id,
        "appId": "",
        "nombre": name,
        "plataforma": type_labels.get(resource_type, "Azure AI"),
        "origen": "Azure Resource Graph",
        "tipoRecurso": resource.get("type"),
        "subscriptionId": resource.get("subscriptionId"),
        "resourceGroup": resource.get("resourceGroup"),
        "location": resource.get("location"),
        "enabled": True,
        "sinPropietario": False,
        "puntuacionRiesgo": 0,
        "nivelRiesgo": "NO EVALUADO",
        "accesoGraphAPI": "No aplica",
        "tipoPermiso": "No evaluado",
        "tipoConsentimiento": "No aplica",
        "editor": "Azure",
        "esPosibleIA": True,
        "enRiesgo": False,
    }


def fetch_defender_cloud_apps(session) -> tuple[list[dict], dict]:
    query = (
        "CloudAppEvents "
        f"| where Timestamp > ago({DEFENDER_HUNTING_LOOKBACK_DAYS}d) "
        "| where isnotempty(Application) "
        "| summarize EventCount=count(), LastSeen=max(Timestamp), UserCount=dcount(AccountObjectId) by Application "
        "| order by EventCount desc "
        "| take 5000"
    )
    try:
        response = session.post(
            "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
            json={"Query": query, "Timespan": "P30D"},
            timeout=10,
        )
        if response.status_code != 200:
            return [], {
                "estado": "ERROR",
                "registros": 0,
                "detalle": f"Microsoft Defender Advanced Hunting respondió HTTP {response.status_code}.",
            }
        data = response.json()
        results = data.get("results", [])
        if not isinstance(results, list):
            return [], {
                "estado": "ERROR",
                "registros": 0,
                "detalle": "Microsoft Defender Advanced Hunting devolvió una respuesta inesperada.",
            }
        return results, {
            "estado": "COMPLETA",
            "registros": len(results),
            "detalle": f"Aplicaciones observadas durante los últimos {DEFENDER_HUNTING_LOOKBACK_DAYS} días.",
        }
    except (requests.RequestException, ValueError, TypeError, AttributeError) as ex:
        return [], {
            "estado": "ERROR",
            "registros": 0,
            "detalle": f"No se pudo consultar Microsoft Defender Advanced Hunting: {str(ex)[:250]}",
        }


def map_defender_app_to_inventory(app: dict) -> dict:
    name = str(app.get("Application") or "Cloud app")
    return {
        "id": f"defender-cloud-app:{name.lower()}",
        "appId": "",
        "nombre": name,
        "plataforma": "Cloud app (Defender)",
        "origen": "Microsoft Defender XDR Advanced Hunting",
        "tipoRecurso": "CloudAppEvents",
        "eventosObservados": app.get("EventCount", 0),
        "usuariosObservados": app.get("UserCount", 0),
        "ultimaActividad": app.get("LastSeen"),
        "enabled": True,
        "sinPropietario": False,
        "puntuacionRiesgo": 0,
        "nivelRiesgo": "NO EVALUADO",
        "accesoGraphAPI": "No evaluado",
        "tipoPermiso": "No evaluado",
        "tipoConsentimiento": "No aplica",
        "editor": "No identificado",
        "esPosibleIA": False,
        "enRiesgo": False,
    }
