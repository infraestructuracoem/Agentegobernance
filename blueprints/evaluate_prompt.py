import json
import azure.functions as func
from shared.config import PALABRAS_PROHIBIDAS
from shared.graph_client import normalizar_texto, es_propietario_gobernanza

bp_evaluate = func.Blueprint()

@bp_evaluate.route(route="evaluate-prompt", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def evaluate_prompt(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "Cuerpo JSON inválido."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    prompt_raw = str(body.get("prompt", "")).strip()
    user_id = str(body.get("userId", "")).strip()

    if not prompt_raw:
        return func.HttpResponse(
            json.dumps({"status": "ERROR", "message": "El campo 'prompt' es obligatorio."}, ensure_ascii=False),
            status_code=400,
            mimetype="application/json"
        )

    if user_id and es_propietario_gobernanza(user_id):
        res = {
            "status": "APPROVED",
            "riskLevel": "BYPASS_ADMIN",
            "userRole": "GOVERNANCE_OWNER",
            "message": "Acceso autorizado por rol de Propietario en GRP Gobernanza IA Purview.",
            "signature": "SIG_GOV_BYPASS_OWNER_OK",
            "respuestaEjecutiva": "ESTADO: APPROVED (BYPASS PROPIETARIO)\nFirma: SIG_GOV_BYPASS_OWNER_OK\nValidación DLP omitida por privilegios de administración de gobernanza."
        }
        return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")

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
        "status": "APPROVED",
        "riskLevel": "LOW",
        "userRole": "STANDARD_USER",
        "message": "Prompt validado correctamente bajo políticas corporativas.",
        "signature": "SIG_GOV_APPROVED_OK",
        "respuestaEjecutiva": "ESTADO: APPROVED\nFirma: SIG_GOV_APPROVED_OK\nNivel de riesgo: LOW. Consulta autorizada."
    }
    return func.HttpResponse(json.dumps(res, ensure_ascii=False), status_code=200, mimetype="application/json")
