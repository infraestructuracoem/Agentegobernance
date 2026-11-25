# Agentegobernance

## Configuración de seguridad

Configura estos valores como *Application Settings* de Azure Function App o desde un almacén de secretos. No guardes los valores reales en el repositorio:

- `AGENT_APPROVAL_HMAC_SECRET`: secreto HMAC de al menos 32 bytes UTF-8.
- `AGENT_APPROVER_EMAILS`: lista separada por comas de correos autorizados para aprobar operaciones.
- `ALLOWED_NOTIFICATION_DOMAINS`: lista separada por comas de dominios exactos autorizados para correo. Por defecto: `coem.co`; no se permiten subdominios automáticamente.

Los despliegues y remediaciones requieren un token emitido por un servicio de aprobación confiable. El token tiene el formato `base64url(payload JSON).base64url(HMAC-SHA256 del primer segmento)` y el payload JSON compacto debe incluir:

```json
{
  "action": "deploy-agent",
  "targetId": "<Object ID>",
  "detailsSha256": "<SHA-256 de los detalles UTF-8>",
  "approvedBy": "aprobador@coem.co",
  "approvalId": "<identificador de aprobación>",
  "issuedAt": 1795630000,
  "expiresAt": 1795630300
}
```

La firma se calcula sobre el primer segmento codificado, con `AGENT_APPROVAL_HMAC_SECRET`; los segmentos Base64 URL-safe no llevan `=` final. El token debe vencer dentro de los 10 minutos posteriores a su emisión. `approvedBy` debe coincidir con `AGENT_APPROVER_EMAILS`.

Trata estos tokens como autorizaciones temporales: limita su exposición en chats, telemetría y registros, y emítelos solo después de comprobar la identidad del aprobador.

Valores de `action` y `details` que se firman:

- Despliegue: `action=deploy-agent`, `targetId=agentObjectId`, `details=solicitud` después de quitar espacios al inicio y al final.
- Cuarentena: `action=quarantine-agent`, `targetId` es el Object ID resuelto del service principal, `details=softdelete`.
- Eliminación definitiva: `action=hard-delete-agent`, `targetId` es el Object ID resuelto del service principal, `details=harddelete`. Además, la solicitud debe incluir `confirmHardDelete=true`.

`detailsSha256` es el hash hexadecimal SHA-256 de `details.encode("utf-8")`. El repositorio no genera tokens: el servicio firmante debe mantener el secreto y validar la identidad y aprobación antes de emitirlos.

La auditoría unificada inventaría aplicaciones registradas y service principals de Entra ID, agentes del catálogo de Microsoft 365 mediante Package Management API v1.0, permisos delegados y de aplicación; además puede buscar recursos de Azure AI mediante Azure Resource Graph y aplicaciones cloud observadas en `CloudAppEvents` mediante Microsoft Defender XDR Advanced Hunting (ventana máxima de 30 días). Azure cubre tipos concretos de Cognitive Services/Azure OpenAI, proyectos de AI Foundry, Machine Learning y Azure Bot Service. Los indicadores de IA se basan en nombres, descripciones y tipo de recurso: son candidatos, no una certificación. Los filtros `all`, `ia`, `agentes`, `riesgo`, `aplicaciones`, `azure_ai` y `defender`, junto con la búsqueda por nombre, ID, App ID o descripción, usan el inventario consolidado y admiten paginación con `limit` y `offset`.

Package Management requiere una licencia de Microsoft Agent 365 y el permiso de aplicación Microsoft Graph `CopilotPackages.Read.All`. Para incorporar agentes de terceros, el administrador debe configurar y sincronizar las plataformas compatibles en Microsoft 365 Admin Center > Agents > Connected platforms; la sincronización es manual. Entre las plataformas documentadas están Amazon Bedrock, Google Vertex AI, Salesforce Agentforce, Databricks Genie y Anthropic Claude Managed Agents. El catálogo no devuelve conectores de Power Platform.

Esto no equivale a descubrir todo el software empresarial: Purview protege, audita y clasifica interacciones de IA, pero no es una API de inventario de aplicaciones; las API de proveedores SaaS tampoco se consultan directamente. Las aplicaciones que no estén registradas en Entra, incluidas en el catálogo de Agent 365 o observadas por Defender no aparecerán. `CloudAppEvents` depende de que Defender for Cloud Apps esté desplegado y reciba datos de los conectores; no es un escaneo universal de red. La cobertura se indica por fuente; una integración ausente o fallida no debe interpretarse como ausencia de aplicaciones.

Configura `AZURE_SUBSCRIPTION_IDS` o `AZURE_MANAGEMENT_GROUP_IDS` para incluir Azure Resource Graph. Asigna al Function App una identidad con acceso Reader a los ámbitos configurados. Defender XDR Advanced Hunting requiere su licencia y consentimiento para el permiso de aplicación Microsoft Graph `ThreatHunting.Read.All`. Los errores de permisos y los servicios no configurados se muestran en la cobertura por fuente, no como inventario completo. El CSV local es únicamente una puntuación auxiliar y su fecha no se verifica. Purview aún no se consulta directamente.

La identidad de Microsoft Graph necesita permisos de aplicación con consentimiento administrativo para leer aplicaciones y service principals; usa además `CopilotPackages.Read.All` (y licencia Agent 365) para el catálogo, y `ThreatHunting.Read.All` para Advanced Hunting. Azure Resource Graph usa un token para `https://management.azure.com/.default` y exige rol Reader en las suscripciones o grupos de administración configurados. Asigna únicamente los permisos mínimos necesarios para las operaciones habilitadas; una falta de permisos se informa por fuente. Consulta la [referencia de permisos de Microsoft Graph](https://learn.microsoft.com/en-us/graph/permissions-reference), [Package Management API](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/package/overview), [plataformas conectadas de Agent 365](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms), [Purview para Agent 365](https://learn.microsoft.com/en-us/purview/ai-agent-365), la [API de Advanced Hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0), [Azure Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview) y la [paginación de consultas](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data).

## Validación local

```powershell
python -m unittest discover -s tests -v
```
