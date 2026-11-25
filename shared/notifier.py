import html
import re
import requests
from datetime import datetime, timezone
from shared.config import (
    ALLOWED_NOTIFICATION_DOMAINS,
    CORREO_REMITENTE_TI,
    CORREO_NOTIFICACIONES_TI,
    FUNCTION_APP_NAME,
)
from shared.graph_client import get_graph_token, create_concurrent_session


def _validar_destinatario(destinatario: str) -> bool:
    if not destinatario or destinatario.count("@") != 1 or any(char.isspace() for char in destinatario):
        return False
    local, domain = destinatario.rsplit("@", 1)
    if not local or len(local) > 64 or len(destinatario) > 254:
        return False
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        return False
    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or ".." in domain:
        return False
    return domain.lower() in ALLOWED_NOTIFICATION_DOMAINS


def enviar_correo_html(asunto: str, cuerpo_html: str, destinatario: str = CORREO_NOTIFICACIONES_TI) -> tuple[bool, str]:
    destino = (destinatario or CORREO_NOTIFICACIONES_TI).strip()
    if not _validar_destinatario(destino):
        return False, "Dirección inválida o dominio no autorizado para notificaciones."

    token = get_graph_token()
    if not token:
        return False, "No se pudo obtener token de autenticación con Microsoft Graph API."

    session = create_concurrent_session(token)
    url_mail = f"https://graph.microsoft.com/v1.0/users/{CORREO_REMITENTE_TI}/sendMail"
    payload = {
        "message": {
            "subject": asunto,
            "body": {"contentType": "HTML", "content": cuerpo_html},
            "toRecipients": [{"emailAddress": {"address": destino}}]
        },
        "saveToSentItems": True
    }

    try:
        resp = session.post(url_mail, json=payload, timeout=12)
        if resp.status_code in [200, 202]:
            return True, f"Correo enviado exitosamente a {destino}."
        return False, f"Error Graph API ({resp.status_code}): {resp.text}"
    except requests.RequestException as ex:
        return False, f"Excepción al enviar correo: {str(ex)}"

def construir_html_auditoria(agents_data: list, criterio: str, metricas: dict | None = None) -> str:
    rows_list = []
    for item in agents_data[:100]:
        nombre = html.escape(str(item.get("nombre", "N/D")))
        plataforma = html.escape(str(item.get("plataforma", "Otros")))
        enabled = bool(item.get("enabled", True))
        state_str = "Habilitado" if enabled else "Deshabilitado"
        state_bg = "#1b4329" if enabled else "#3b1d1d"
        state_color = "#51cf66" if enabled else "#ff6b6b"
        score = int(item.get("puntuacionRiesgo", 70))
        score_bg = "#d9381e" if score >= 71 else ("#f08c00" if score == 70 else "#2b8a3e")

        acceso_graph = html.escape(str(item.get("accesoGraphAPI", "Sí")))
        tipo_permiso = html.escape(str(item.get("tipoPermiso", "Delegado")))
        tipo_consent = html.escape(str(item.get("tipoConsentimiento", "Usuario")))
        editor = html.escape(str(item.get("editor", "N/D")))

        rows_list.append(
            f'<tr style="border-bottom: 1px solid #2d2d2d; font-size: 13px;">'
            f'<td style="padding: 10px; color: #ffffff; font-weight: 600;">{nombre}</td>'
            f'<td style="padding: 10px; color: #8b949e;">{plataforma}</td>'
            f'<td style="padding: 10px;"><span style="background: {state_bg}; color: {state_color}; padding: 2px 8px; border-radius: 12px; font-size: 11px;">{state_str}</span></td>'
            f'<td style="padding: 10px; text-align: center;"><span style="background-color: {score_bg}; color: #ffffff; font-weight: bold; padding: 4px 10px; border-radius: 50%; display: inline-block; min-width: 24px;">{score}</span></td>'
            f'<td style="padding: 10px; color: #cccccc; text-align: center;">{acceso_graph}</td>'
            f'<td style="padding: 10px; color: #cccccc;">{tipo_permiso}</td>'
            f'<td style="padding: 10px; color: #cccccc;">{tipo_consent}</td>'
            f'<td style="padding: 10px; color: #cccccc;">{editor}</td>'
            f'</tr>'
        )

    rows_html = "\n".join(rows_list) if rows_list else (
        '<tr><td colspan="8" style="padding: 16px; text-align: center; color: #8b949e;">Sin registros para el filtro aplicado.</td></tr>'
    )
    resumen_html = ""
    if metricas:
        resumen_html = (
            f'<p style="color: #8b949e; font-size: 13px;">'
            f'<strong>Total Inventario:</strong> {metricas.get("totalAgentes", 0)} | '
            f'<strong>En Riesgo (≥70):</strong> {metricas.get("agentesEnRiesgo", 0)} | '
            f'<strong>No Administrados:</strong> {metricas.get("agentesNoAdministrados", 0)}'
            f' | <strong>Cobertura fuentes:</strong> {html.escape(str(metricas.get("coberturaFuentes", "PARCIAL")))}</p>'
        )
        if metricas.get("coberturaPermisosAplicacion"):
            resumen_html += (
                f'<p style="color: #f08c00; font-size: 13px;">'
                f'<strong>Cobertura de permisos de aplicación:</strong> '
                f'{html.escape(str(metricas["coberturaPermisosAplicacion"]))}</p>'
            )

    return (
        '<html><body style="font-family: \'Segoe UI\', sans-serif; background-color: #0f1117; color: #e0e0e0; padding: 20px;">'
        '<div style="max-width: 1150px; margin: 0 auto; background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px;">'
        '<h2 style="color: #58a6ff; margin-top: 0;">REPORTE DE AUDITORÍA DE GOBERNANZA DE IA</h2>'
        f'<p style="color: #8b949e; font-size: 14px;"><strong>Criterio:</strong> {html.escape(criterio)} | <strong>Registros:</strong> {len(agents_data[:100])}</p>'
        f'{resumen_html}'
        '<table style="width: 100%; border-collapse: collapse; margin-top: 16px; text-align: left; background-color: #0d1117;">'
        '<thead><tr style="background-color: #21262d; color: #8b949e; border-bottom: 2px solid #30363d; font-size: 12px; text-transform: uppercase;">'
        '<th style="padding: 12px 10px;">Nombre</th><th style="padding: 12px 10px;">Plataforma</th><th style="padding: 12px 10px;">Estado</th>'
        '<th style="padding: 12px 10px; text-align: center;">Riesgo</th><th style="padding: 12px 10px; text-align: center;">Graph API</th>'
        '<th style="padding: 12px 10px;">Permiso</th><th style="padding: 12px 10px;">Consentimiento</th><th style="padding: 12px 10px;">Editor</th>'
        f'</tr></thead><tbody>{rows_html}</tbody></table>'
        '<hr style="border: 0; border-top: 1px solid #30363d; margin-top: 24px;"/>'
        '<p style="font-size: 11px; color: #8b949e; text-align: center;">AGENTE-GOBERNANZA-CORE | Microsoft Graph y snapshot local de Defender | Reporte informativo, no es una firma digital</p>'
        '</div></body></html>'
    )

def construir_html_evento(titulo: str, color_acento: str, badge: str, detalles: dict) -> str:
    fecha_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    filas = []
    for clave, valor in detalles.items():
        filas.append(
            f'<tr style="border-bottom: 1px solid #30363d;">'
            f'<td style="padding: 10px; color: #8b949e; width: 220px; font-weight: 600;">{html.escape(str(clave))}</td>'
            f'<td style="padding: 10px; color: #f0f6fc;">{html.escape(str(valor))}</td>'
            f'</tr>'
        )
    filas_html = "\n".join(filas)
    return (
        '<html><body style="font-family: \'Segoe UI\', sans-serif; background-color: #0f1117; color: #e0e0e0; padding: 20px;">'
        '<div style="max-width: 780px; margin: 0 auto; background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px;">'
        f'<span style="background-color: {color_acento}; color: #ffffff; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;">{html.escape(badge)}</span>'
        f'<h2 style="color: #ffffff; margin-top: 12px;">{html.escape(titulo)}</h2>'
        '<table style="width: 100%; border-collapse: collapse; margin-top: 16px; background-color: #0d1117; font-size: 13px;">'
        f'<tbody>{filas_html}</tbody></table>'
        '<hr style="border: 0; border-top: 1px solid #30363d; margin-top: 24px;"/>'
        f'<p style="font-size: 11px; color: #8b949e;">Generado por {FUNCTION_APP_NAME} el {fecha_utc} | Reporte informativo, no es una firma digital</p>'
        '</div></body></html>'
    )
