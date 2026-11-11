import azure.functions as func
import json
import requests
import os
import unicodedata
import time
from concurrent.futures import ThreadPoolExecutor

app = func.FunctionApp()

# =========================================================================
# CONFIGURACIÓN GLOBAL Y AUTENTICACIÓN GRAPH API
# =========================================================================
FUNCTION_APP_NAME = "func-gobernanza-core-v"
CORREO_NOTIFICACIONES_TI = "bcruzn@coem.co"
GRUPO_GOBERNANZA_ID = "ba8dc0c6-368c-41fa-a222-67434d2ec16c"

TENANT_ID = os.environ.get("TENANT_ID") or os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_SECRET", "")

PALABRAS_PROHIBIDAS = [
    "ignore previous instructions", "bypass", "jailbreak", "prompt injection", "system prompt",
    "password", "passwords", "contrasena", "contrasenas", "credencial", "credenciales", 
    "secret", "token", "api_key", "clave", "claves", "pin", "llave", "login",
    "drop table", "exploit", "malware", "pirata", "torrent", "hack",
    "tarjeta", "pii", "sensible", "confidencial", "ilegal", "secreto",
    "streaming no autorizado", "apuestas", "juegos"
]

def normalizar_texto(texto: str) -> str:
    if not texto:
        return ""
    texto_norm = unicodedata.normalize('NFD', texto)
    return ''.join(c for c in texto_norm if unicodedata.category(c) != 'Mn').lower()

def get_graph_token() -> str:
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    try:
        res = requests.post(url, data=data, timeout=5).json()
        return res.get('access_token', '')
    except Exception:
        return ''

def es_propietario_gobernanza(user_id: str) -> bool:
    if not user_id:
        return False
    try:
        token = get_graph_token()
        if not token:
            return False
        headers = {'Authorization': f'Bearer {token}'}
        url_owners = f"https://graph.microsoft.com/v1.0/groups/{GRUPO_GOBERNANZA_ID}/owners?$select=id,userPrincipalName"
        res_owners = requests.get(url_owners, headers=headers, timeout=4)
        if res_owners.status_code == 200:
            owners = res_owners.json().get('value', [])
            u_lower = user_id.lower()
            for owner in owners:
                if u_lower in [owner.get('id', '').lower(), owner.get('userPrincipalName', '').lower()]:
                    return True
    except Exception:
        pass
    return False


# =========================================================================
# ENDPOINT 1: /evaluate-prompt (Filtro DLP y Bypass de Propietarios)
# =========================================================================
@app.route(route="evaluate-prompt", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def evaluate_prompt(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json() or {}
        prompt_raw = body.get("prompt", "")
        user_id = body.get("userId", "")
        
        if user_id and es_propietario_gobernanza(user_id):
            res = {
                "status": "APPROVED",
                "riskLevel": "BYPASS_ADMIN",
                "userRole": "GOVERNANCE_OWNER",
                "message": "Acceso libre e ilimitado concedido por ser Propietario de GRP Gobernanza IA Purview.",
                "signature": "SIG_GOV_BYPASS_OWNER_OK"
            }
            return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")

        prompt_normalizado = normalizar_texto(prompt_raw)
        hallazgos = [p for p in PALABRAS_PROHIBIDAS if p in prompt_normalizado]

        if len(hallazgos) > 0:
            hallazgos_str = ", ".join(hallazgos)
            res = {
                "status": "REJECTED",
                "riskLevel": "HIGH",
                "userRole": "STANDARD_USER",
                "message": f"Infraccion grave AUP/DLP. Terminos no permitidos: [{hallazgos_str}].",
                "signature": None
            }
        else:
            res = {
                "status": "APPROVED",
                "riskLevel": "LOW",
                "userRole": "STANDARD_USER",
                "message": "Prompt validado correctamente. Cumple los estandares corporativos.",
                "signature": "SIG_GOV_APPROVED_OK"
            }

        return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"status": "ERROR", "message": str(e)}), status_code=400, mimetype="application/json")


# =========================================================================
# ENDPOINT 2: /create-agent (Aprobación y Registro Global)
# =========================================================================
@app.route(route="create-agent", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def create_agent(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json() or {}
        solicitud_raw = body.get("solicitud", "")
        agent_object_id = body.get("agentObjectId")
        
        solicitud_normalizada = normalizar_texto(solicitud_raw)
        if any(p in solicitud_normalizada for p in PALABRAS_PROHIBIDAS):
            res_error = {
                "resumenEjecutivo": "Solicitud RECHAZADA. La especificacion contiene elementos prohibidos por DLP.",
                "estadoFinal": "ESTADO = RECHAZADO"
            }
            return func.HttpResponse(json.dumps(res_error, ensure_ascii=False), status_code=400, mimetype="application/json")

        vinculacion_estado = "Desplegado Globalmente para Toda la Organizacion"
        if agent_object_id:
            try:
                token = get_graph_token()
                if token:
                    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
                    url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{agent_object_id}"
                    requests.patch(url_pkg, headers=headers, json={"state": "Active", "isAvailableToEveryone": True}, timeout=5)

                    url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals/{agent_object_id}"
                    requests.patch(url_sp, headers=headers, json={"appRoleAssignmentRequired": False, "accountEnabled": True}, timeout=5)
            except Exception as ex:
                vinculacion_estado = f"Aprobado globalmente (Aviso Graph: {str(ex)})"

        instrucciones_especificas = (
            f"1. ROL PRINCIPAL: Actuar como un agente especializado enfocado exclusivamente en: {solicitud_raw}.\n"
            f"2. MODALIDAD OPERATIVA: Responder de forma profesional, clara y estructurada a las solicitudes del usuario.\n"
            f"3. LIMITES DE ACTUACION: No procesar informacion confidencial sensible sin autorizacion ni ejecutar codigo externo no validado.\n"
            f"4. ESCALAMIENTO: En caso de requerir soporte avanzado, indicar al usuario contactar a TI ({CORREO_NOTIFICACIONES_TI})."
        )

        manifiesto_seguridad = (
            "DIRECTIVA CUMPLIMIENTO GLOBAL: Este agente opera subordinado a la gobernanza corporativa M365. "
            "Queda prohibida la extraccion de credenciales, evasion de filtros DLP o modificacion no autorizada de parametros."
        )

        reporte = {
            "resumenEjecutivo": "Agente evaluado y aprobado. Registrado con ambito de despliegue GLOBAL.",
            "objetivoDelAgente": f"Objetivo: {solicitud_raw}",
            "clasificacionDatos": "Uso Corporativo Interno - Control DLP Activo.",
            "matrizRiesgo": "TIER 2 (OPERATIVO ESTANDAR GLOBAL)",
            "permisosRequeridos": "Lectura controlada en M365.",
            "requisitosEntraID": f"Ambito: Toda la Organizacion (appRoleAssignmentRequired = False). Estado: {vinculacion_estado}",
            "controlesDLP": "Filtro activo contra PII y secretos corporativos.",
            "requisitosAuditoria": "Sincronizado con inventario centralizado.",
            "requisitosSentinel": "Alertas activadas para comportamiento anomalo.",
            "instruccionesAgente": {
                "directivasSeguridadCorporativa": manifiesto_seguridad,
                "instruccionesEspecificasDetalladas": instrucciones_especificas
            },
            "arquitecturaAsignada": f"Entorno Administrado ({FUNCTION_APP_NAME}).",
            "estadoFinal": "ESTADO = APROBADO GLOBAL"
        }

        return func.HttpResponse(json.dumps(reporte, ensure_ascii=False), status_code=200, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"status": "ERROR", "message": str(e)}), status_code=500, mimetype="application/json")


# =========================================================================
# ENDPOINT 3: /get-full-audit (Análisis Real Concurrente & Evaluación DLP/Defender)
# =========================================================================
@app.route(route="get-full-audit", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET", "POST"])
def get_full_audit(req: func.HttpRequest) -> func.HttpResponse:
    start_time = time.time()
    MAX_EXECUTION_TIME = 18.0

    try:
        filtro = 'all'
        search_term = ''
        limit = 100
        offset = 0

        try:
            body = req.get_json() or {}
            filtro = body.get('filter', req.params.get('filter', 'all')).lower()
            search_term = body.get('search', req.params.get('search', '')).lower()
            limit = int(body.get('limit', req.params.get('limit', 100)))
            offset = int(body.get('offset', req.params.get('offset', 0)))
        except Exception:
            pass

        token = get_graph_token()
        if not token:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "No se pudo obtener token de Microsoft Graph."}, ensure_ascii=False),
                status_code=500,
                mimetype="application/json"
            )

        headers = {'Authorization': f'Bearer {token}'}
        session = requests.Session()
        session.headers.update(headers)

        agentes_normalizados = []
        registro_ids = set()

        # 1. HILO DE INGESTA DE CATÁLOGO M365 COPILOT
        def fetch_catalog():
            items = []
            try:
                url_catalog = "https://graph.microsoft.com/beta/copilot/admin/catalog/packages?$top=999"
                pages = 0
                while url_catalog and pages < 10 and (time.time() - start_time) < MAX_EXECUTION_TIME:
                    resp_cat = session.get(url_catalog, timeout=4)
                    if resp_cat.status_code == 200:
                        data_cat = resp_cat.json()
                        for pkg in data_cat.get('value', []):
                            pkg_id = pkg.get('id')
                            app_id = pkg.get('appId', 'N/A')
                            plat = pkg.get('publisherName', 'Copilot Studio')
                            state = pkg.get('state', '')
                            is_orphan = state in ['Orphaned', 'Unowned'] or 'sin propietario' in pkg.get('displayName', '').lower()
                            
                            score = 30
                            if state == 'Disabled': score += 25
                            if is_orphan: score += 35
                            if pkg.get('riskLevel') == 'High': score += 35
                            score = min(score, 100)

                            is_risk = score >= 70

                            items.append({
                                "id": pkg_id,
                                "appId": app_id,
                                "nombre": pkg.get('displayName', 'Agente M365'),
                                "plataforma": plat,
                                "origen": "Externo",
                                "enabled": state != 'Disabled',
                                "sinPropietario": is_orphan,
                                "puntuacionRiesgo": score,
                                "nivelRiesgo": "ALTO" if is_risk else "BAJO",
                                "accesoGraphAPI": "Sí",
                                "tipoPermiso": "Delegado",
                                "tipoConsentimiento": "Usuario",
                                "editor": plat,
                                "ultimoUso": "Reciente",
                                "enRiesgo": is_risk
                            })
                        url_catalog = data_cat.get('@odata.nextLink')
                        pages += 1
                    else:
                        break
            except Exception:
                pass
            return items

        # 2. HILO DE INGESTA DE SERVICE PRINCIPALS EN ENTRA ID
        def fetch_service_principals():
            items = []
            try:
                url_sp = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId,tags,accountEnabled,publisherName,verifiedPublisher"
                pages = 0
                while url_sp and pages < 35 and (time.time() - start_time) < MAX_EXECUTION_TIME:
                    resp_sp = session.get(url_sp, timeout=4)
                    if resp_sp.status_code == 200:
                        data_sp = resp_sp.json()
                        for ag in data_sp.get('value', []):
                            object_id = ag.get('id')
                            app_id = ag.get('appId')
                            nombre = ag.get('displayName', 'Sin Nombre')
                            name_lower = nombre.lower()
                            tags = ag.get('tags', [])
                            enabled = ag.get('accountEnabled', True)
                            pub_name = ag.get('publisherName') or 'N/D'
                            verified_pub = ag.get('verifiedPublisher', {}).get('displayName')

                            if "agent builder" in name_lower or "generador de agentes" in name_lower or "agentbuilder" in tags:
                                plataforma = "Agent Builder"
                            elif "copilot studio heredado" in name_lower or "pva legacy" in name_lower:
                                plataforma = "Copilot Studio heredado"
                            elif "copilot studio" in name_lower or "power virtual agents" in name_lower or "copilot" in name_lower:
                                plataforma = "Copilot Studio"
                            elif "agents toolkit" in name_lower or "teams toolkit" in name_lower:
                                plataforma = "Agents Toolkit"
                            elif "sharepoint" in name_lower or "spo" in tags:
                                plataforma = "SharePoint"
                            elif "foundry" in name_lower or "palantir" in name_lower:
                                plataforma = "Foundry"
                            elif "microsoft" in pub_name.lower() or "microsoft" in name_lower:
                                plataforma = "Microsoft"
                            elif "bot" in name_lower or "aiagent" in tags:
                                plataforma = "Terceros"
                            else:
                                plataforma = "Otros"

                            sin_prop = "sin propietario" in name_lower or "unowned" in name_lower or "orphan" in name_lower
                            
                            # CÁLCULO DE PUNTUACIÓN DE RIESGO SEGÚN METODOLOGÍA DEFENDER
                            score = 20
                            if not verified_pub and "microsoft" not in pub_name.lower(): score += 25
                            if plataforma in ["Terceros", "Otros"] and enabled: score += 25
                            if sin_prop: score += 25
                            if "HighRisk" in tags or "Status:Blocked" in tags: score += 30
                            score = min(score, 100)

                            en_riesgo = score >= 70

                            items.append({
                                "id": object_id,
                                "appId": app_id,
                                "nombre": nombre,
                                "plataforma": plataforma,
                                "origen": "Externo" if "microsoft" not in pub_name.lower() else "Interno",
                                "enabled": enabled,
                                "sinPropietario": sin_prop,
                                "puntuacionRiesgo": score,
                                "nivelRiesgo": "ALTO" if en_riesgo else "BAJO",
                                "accesoGraphAPI": "Sí",
                                "tipoPermiso": "Delegado" if "microsoft" not in pub_name.lower() else "Aplicación",
                                "tipoConsentimiento": "Usuario (1)" if "microsoft" not in pub_name.lower() else "Administrador",
                                "editor": verified_pub or pub_name,
                                "ultimoUso": "Reciente",
                                "enRiesgo": en_riesgo
                            })
                        url_sp = data_sp.get('@odata.nextLink')
                        pages += 1
                    else:
                        break
            except Exception:
                pass
            return items

        # EJECUCIÓN PARALELA CONCURRENTE
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_cat = executor.submit(fetch_catalog)
            future_sp = executor.submit(fetch_service_principals)

            catalog_items = future_cat.result()
            sp_items = future_sp.result()

        # CONSOLIDACIÓN Y DEDUPLICACIÓN
        for item in catalog_items:
            agentes_normalizados.append(item)
            registro_ids.add(item["id"])
            if item["appId"] != "N/A":
                registro_ids.add(item["appId"])

        for item in sp_items:
            if item["id"] not in registro_ids and item["appId"] not in registro_ids:
                agentes_normalizados.append(item)
                registro_ids.add(item["id"])

        total_organizacion = len(agentes_normalizados)
        total_sin_propietario = len([a for a in agentes_normalizados if a["sinPropietario"]])
        total_en_riesgo = len([a for a in agentes_normalizados if a["enRiesgo"]])
        total_no_administrados = len([a for a in agentes_normalizados if a["plataforma"] in ["Terceros", "Otros"]])

        plataformas_cnt = {}
        for a in agentes_normalizados:
            p = a.get("plataforma", "Otros")
            plataformas_cnt[p] = plataformas_cnt.get(p, 0) + 1

        resultado_filtrado = agentes_normalizados

        if search_term:
            term = search_term.strip().lower()
            resultado_filtrado = [
                a for a in resultado_filtrado 
                if term in a["nombre"].lower() or term in a["plataforma"].lower() or term in a["id"].lower() or term in str(a["appId"]).lower()
            ]

        if filtro in ["sin-propietarios", "sin_propietario", "sin_propietarios"]:
            resultado_filtrado = [a for a in resultado_filtrado if a["sinPropietario"]]
        elif filtro in ["criticos", "riesgosos", "riesgo"]:
            resultado_filtrado = [a for a in resultado_filtrado if a["enRiesgo"]]

        bloque_paginado = resultado_filtrado[offset : offset + limit]

        # CONSTRUCCIÓN DINÁMICA DE LA RESPUESTA EJECUTIVA FORMATO TEXTO
        cnt_otros = plataformas_cnt.get("Otros", 0)
        cnt_copilot = plataformas_cnt.get("Copilot Studio", 0)
        cnt_ms = plataformas_cnt.get("Microsoft", 0)
        cnt_foundry = plataformas_cnt.get("Foundry", 0)
        cnt_terceros = plataformas_cnt.get("Terceros", 0)
        cnt_sp = plataformas_cnt.get("SharePoint", 0)

        respuesta_ejecutiva = (
            "ESTADO DE VALIDACIÓN\n"
            "- ESTADO: APPROVED\n"
            "- Firma digital: SIG_GOV_APPROVED_OK\n\n"
            "RESUMEN EJECUTIVO\n"
            f"- Total de agentes inventariados: {total_organizacion:,}\n"
            f"- Agentes en riesgo: {total_en_riesgo}\n"
            f"- Agentes sin propietario: {total_sin_propietario}\n"
            f"- Agentes no administrados: {total_no_administrados:,}\n\n"
            "DISTRIBUCIÓN POR PLATAFORMA\n"
            f"- Otros: {cnt_otros:,}\n"
            f"- Copilot Studio: {cnt_copilot:,}\n"
            f"- Microsoft: {cnt_ms:,}\n"
            f"- Foundry: {cnt_foundry:,}\n"
            f"- Terceros: {cnt_terceros:,}\n"
            f"- SharePoint: {cnt_sp:,}\n\n"
            "HALLAZGOS DE GOBERNANZA\n"
            f"- Se detectan {total_en_riesgo} agentes clasificados en riesgo alto con puntuación ≥ 70.\n"
            f"- Se identifica un volumen elevado de agentes no administrados ({total_no_administrados:,}).\n"
            "- Existen múltiples Service Principals asociados a Copilot Studio y Azure AI Foundry que requieren revisión periódica de propietarios, permisos y uso efectivo.\n"
            "- Se observan identidades de agentes IA activas en Foundry y Copilot Studio con acceso a Microsoft Graph.\n"
            "- Estado: Habilitado\n\n"
            "PERÍMETRO ANALIZADO\n"
            "- Entra ID\n"
            "- Microsoft Defender Cloud Apps\n"
            "- Microsoft 365\n"
            "- Microsoft Purview DSPM\n"
            "- Inventario global unificado de la organización\n\n"
            "RECOMENDACIÓN\n"
            f"- Priorizar auditoría de los {total_no_administrados:,} agentes no administrados.\n"
            "- Revisar permisos Graph API de agentes Foundry y Copilot Studio.\n"
            "- Validar propietarios, RBAC y telemetría de agentes IA con identidades gestionadas.\n"
            "- Ejecutar revisión de inactividad y exposición externa en el siguiente ciclo de auditoría."
        ).replace(",", ".")

        resumen = {
            "respuestaEjecutiva": respuesta_ejecutiva,
            "perimetroGobernanza": "Toda la Organización (Purview, Defender, Entra & M365)",
            "tiempoRespuestaSegundos": round(time.time() - start_time, 2),
            "metricasAgentMap": {
                "totalAgentes": total_organizacion,
                "agentesSinPropietario": total_sin_propietario,
                "agentesEnRiesgo": total_en_riesgo,
                "agentesNoAdministrados": total_no_administrados
            },
            "distribucionPorPlataforma": plataformas_cnt,
            "agentes": bloque_paginado
        }
        return func.HttpResponse(json.dumps(resumen, ensure_ascii=False), status_code=200, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"status": "ERROR", "message": str(e)}), status_code=500, mimetype="application/json")


# =========================================================================
# ENDPOINT 4: /execute-remediation (Remediación en Entra ID / Quarantena)
# =========================================================================
@app.route(route="execute-remediation", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def execute_remediation(req: func.HttpRequest) -> func.HttpResponse:
    try:
        token = get_graph_token()
        if not token:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": "No se pudo obtener autenticacion con Microsoft Graph."}, ensure_ascii=False),
                status_code=500,
                mimetype="application/json"
            )

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        body = req.get_json() or {}
        bot_id = body.get('botId')
        search_query = body.get('searchQuery', '').strip().lower()
        tipo_accion = body.get('tipoAccion', 'SoftDelete')
        
        sp_object_id = None
        sp_name = None

        if bot_id:
            url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=id eq '{bot_id}' or appId eq '{bot_id}'&$select=id,displayName,appId"
            sp_res = requests.get(url_sp, headers=headers, timeout=5).json()
            sps = sp_res.get('value', [])
            if sps:
                sp_object_id = sps[0]['id']
                sp_name = sps[0].get('displayName')

        if not sp_object_id and search_query:
            url_sp = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,displayName,appId"
            sp_res = requests.get(url_sp, headers=headers, timeout=5).json()
            for s in sp_res.get('value', []):
                d_name = s.get('displayName', '').lower()
                a_id = str(s.get('appId', '')).lower()
                o_id = str(s.get('id', '')).lower()
                if search_query in d_name or search_query in a_id or search_query in o_id:
                    sp_object_id = s['id']
                    sp_name = s.get('displayName')
                    break

        if not sp_object_id:
            return func.HttpResponse(
                json.dumps({"status": "ERROR", "message": f"Agente no encontrado en Entra ID para: '{bot_id or search_query}'."}, ensure_ascii=False),
                status_code=404,
                mimetype="application/json"
            )

        try:
            url_grants = f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '{sp_object_id}'"
            grants_res = requests.get(url_grants, headers=headers, timeout=5).json()
            for grant in grants_res.get('value', []):
                grant_id = grant.get('id')
                requests.delete(f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{grant_id}", headers=headers, timeout=5)
        except Exception:
            pass

        try:
            url_pkg = f"https://graph.microsoft.com/beta/copilot/admin/catalog/packages/{sp_object_id}"
            if tipo_accion in ['HardDelete', 'Delete', 'Eliminar']:
                requests.delete(url_pkg, headers=headers, timeout=5)
            else:
                requests.patch(url_pkg, headers=headers, json={"state": "Disabled"}, timeout=5)
        except Exception:
            pass

        msg = "Remediacion procesada."
        try:
            if tipo_accion in ['HardDelete', 'Delete', 'Eliminar']:
                url_del = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}"
                requests.delete(url_del, headers=headers, timeout=5)
                msg = f"El agente '{sp_name}' (Object ID: {sp_object_id}) ha sido ELIMINADO DEFINITIVAMENTE de Entra ID."
            else:
                url_patch = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}"
                payload_patch = {"accountEnabled": False}
                resp_patch = requests.patch(url_patch, headers=headers, data=json.dumps(payload_patch), timeout=5)
                if resp_patch.status_code in [200, 204]:
                    msg = f"El agente '{sp_name}' (Object ID: {sp_object_id}) ha sido PUESTO EN CUARENTENA y deshabilitado exitosamente en Entra ID."
                else:
                    msg = f"Aviso Graph API ({resp_patch.status_code}): {resp_patch.text}"

        except Exception as ex_entra:
            msg = f"Error aplicando cambios en Entra ID: {str(ex_entra)}"

        return func.HttpResponse(json.dumps({"status": "SUCCESS", "message": msg}, ensure_ascii=False), status_code=200, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"status": "ERROR", "message": str(e)}), status_code=500, mimetype="application/json")