import json

import azure.functions as func

from blueprints.get_full_audit import ejecutar_inventario_concurrente

bp_audit = func.Blueprint()


@bp_audit.route(route="get-full-audit", auth_level=func.AuthLevel.FUNCTION, methods=["GET", "POST"])
def get_full_audit(req: func.HttpRequest) -> func.HttpResponse:
    filtro = str(req.params.get("filter", "all")).strip().lower()
    search_term = str(req.params.get("search", "")).strip()
    limit = req.params.get("limit", "100")
    offset = req.params.get("offset", "0")

    if req.method == "POST":
        try:
            body = req.get_json()
        except ValueError:
            return _json_response({"status": "ERROR", "message": "Cuerpo JSON inválido."}, 400)
        if not isinstance(body, dict):
            return _json_response({"status": "ERROR", "message": "El cuerpo debe ser un objeto JSON."}, 400)
        filtro = str(body.get("filter", filtro)).strip().lower()
        search_term = str(body.get("search", search_term)).strip()
        limit = body.get("limit", limit)
        offset = body.get("offset", offset)

    try:
        page_size = max(1, min(int(limit), 500))
        page_offset = max(0, min(int(offset), 50000))
    except (TypeError, ValueError):
        return _json_response(
            {"status": "ERROR", "message": "'limit' y 'offset' deben ser enteros."},
            400,
        )

    audit = ejecutar_inventario_concurrente(
        filtro=filtro or "all",
        search_term=search_term,
        limit=page_size,
        offset=page_offset,
    )
    if "error" in audit:
        return _json_response(
            {
                "status": "ERROR",
                "message": audit["error"],
                "estadoCobertura": "PARCIAL",
                "fuentes": audit.get("fuentes", {}),
            },
            502,
        )

    metrics = audit["metricasGlobales"]
    source_lines = [
        f"- {name}: {source.get('estado', 'NO DISPONIBLE')} "
        f"({source.get('registros', 0)} registros)"
        for name, source in audit["fuentes"].items()
        if isinstance(source, dict)
    ]
    results = audit["agentes"]
    if search_term or filtro != "all":
        response_text = (
            f"RESULTADOS DE INVENTARIO ({filtro}; búsqueda: {search_term or 'sin término'})\n"
            f"- Coincidencias: {audit['totalFiltrados']}\n"
            f"- Página: {page_offset + 1}-{page_offset + len(results)} de {audit['totalFiltrados']}\n"
            f"- Aplicaciones registradas: {metrics['totalAplicaciones']}; posibles IA: {metrics['posiblesAgentesIA']}; "
            f"agentes del catálogo: {metrics['totalAgentesRegistrados']}; "
            f"en riesgo: {metrics['agentesEnRiesgo']}.\n"
            f"- Cobertura: {audit['estadoCobertura']}.\n\n"
        )
    else:
        response_text = (
            "MAPEO EMPRESARIAL DE APLICACIONES Y SERVICIOS DE IA\n"
            f"- Estado de cobertura: {audit['estadoCobertura']}.\n"
            f"- Aplicaciones de Entra ID: {metrics['totalAplicaciones']}.\n"
            f"- Agentes del catálogo Microsoft 365: {metrics.get('totalAgentesRegistrados', 0)}.\n"
            f"- Posibles agentes/aplicaciones de IA: {metrics['posiblesAgentesIA']}.\n"
            f"- Aplicaciones observadas en Defender: {metrics['aplicacionesCloudObservadas']}.\n"
            f"- Recursos Azure AI: {metrics['recursosAzureIA']}.\n"
            f"- Coincidencias del filtro: {audit['totalFiltrados']}.\n"
            "- El inventario clasifica candidatos por metadatos; no certifica que una aplicación sea un agente de IA.\n\n"
        )

    formatted_results = []
    for index, item in enumerate(results, start=page_offset + 1):
        formatted_results.append(
            f"{index}. {item['nombre']} | {item['plataforma']} | "
            f"IA posible: {'sí' if item.get('esPosibleIA') else 'no'} | "
            f"Riesgo: {item['puntuacionRiesgo']}/100 ({item['nivelRiesgo']}) | "
            f"Origen: {item['origen']} | ID: {item['id']}"
        )
    response_text += "FUENTES\n" + "\n".join(source_lines)
    if formatted_results:
        response_text += "\n\nRESULTADOS\n" + "\n".join(formatted_results[:50])
        if len(formatted_results) > 50:
            response_text += "\n- Usa offset para consultar los siguientes resultados."

    return _json_response({
        "status": "SUCCESS",
        "respuestaEjecutiva": response_text,
        "estadoCobertura": audit["estadoCobertura"],
        "fuentes": audit["fuentes"],
        "metricasGlobales": metrics,
        "metricasAgentMap": audit["metricasAgentMap"],
        "coberturaPermisosAplicacion": audit["fuentes"]["appRoleAssignments"]["estado"],
        "tiempoRespuestaSegundos": audit["tiempoRespuestaSegundos"],
        "totalFiltrados": audit["totalFiltrados"],
        "limit": page_size,
        "offset": page_offset,
        "tieneMasResultados": page_offset + len(results) < audit["totalFiltrados"],
        "agentes": results,
    })


def _json_response(payload: dict, status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, ensure_ascii=False),
        status_code=status_code,
        mimetype="application/json",
    )
