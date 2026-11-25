import json
import azure.functions as func
from shared.config import PALABRAS_PROHIBIDAS
from shared.graph_client import normalizar_texto

bp_evaluate = func.Blueprint()

@bp_evaluate.route(route="evaluate-prompt", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def evaluate_prompt(req: func.HttpRequest) -> func.HttpResponse:
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

    prompt_raw = str(body.get("prompt", "")).strip()

    if not prompt_raw:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "El campo 'prompt' es obligatorio."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    prompt_norm = normalizar_texto(prompt_raw)
    hallazgos = [p for p in PALABRAS_PROHIBIDAS if p in prompt_norm]

    if hallazgos:
        hallazgos_str = ", ".join(hallazgos)
        res = {
            "status": "REJECTED",
            "riskLevel": "HIGH",
            "userRole": "STANDARD_USER",
            "message": f"Infracción de directiva AUP/DLP. Términos detectados: [{hallazgos_str}].",
            "signature": None,
            "respuestaEjecutiva": (
                "ESTADO: REJECTED (ALERTA DLP)\n"
                f"Motivo: Se detectaron patrones restringidos por política corporativa ({hallazgos_str}).\n"
                "Acción: Solicitud bloqueada."
            )
        }
        return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")

    res = {
        "status": "NEEDS_REVIEW",
        "riskLevel": "UNASSESSED",
        "userRole": "STANDARD_USER",
        "message": "No se detectaron términos de la lista; esto no constituye una aprobación de seguridad.",
        "signature": None,
        "respuestaEjecutiva": (
            "ESTADO: REVISIÓN REQUERIDA\n"
            "No se detectaron términos coincidentes con la lista de bloqueo. "
            "La comprobación por palabras clave no evalúa el contexto ni autoriza la solicitud."
        )
    }
    return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")
