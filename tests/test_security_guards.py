import base64
import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import patch

from blueprints.evaluate_prompt import evaluate_prompt
from blueprints.get_full_audit import (
    _fetch_app_role_assignments,
    _marcar_clasificacion_ia,
    _score_defender,
    ejecutar_inventario_concurrente,
)
from blueprints import create_agent as create_agent_module
from blueprints import audit_endpoint
from blueprints import get_full_audit as audit_module
from shared import enterprise_sources
from shared import agent_approval, notifier


def _approval_token(action, target_id, details, secret, issued_at=None, expires_at=None, approved_by="approver@coem.co"):
    now = int(time.time())
    payload = {
        "action": action,
        "targetId": target_id,
        "detailsSha256": hashlib.sha256(details.encode("utf-8")).hexdigest(),
        "approvedBy": approved_by,
        "approvalId": "approval-123",
        "issuedAt": now if issued_at is None else issued_at,
        "expiresAt": now + 300 if expires_at is None else expires_at,
    }
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{encoded_payload}.{encoded_signature}"


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.secret = "test-secret-with-at-least-32-bytes"
        self.config = (
            patch.object(agent_approval, "AGENT_APPROVAL_HMAC_SECRET", self.secret),
            patch.object(agent_approval, "AGENT_APPROVER_EMAILS", frozenset({"approver@coem.co"})),
        )
        for item in self.config:
            item.start()
            self.addCleanup(item.stop)

    def test_accepts_valid_scoped_approval(self):
        token = _approval_token("deploy-agent", "object-1", "agent objective", self.secret)
        result = agent_approval.validar_aprobacion_operacion(
            token, "deploy-agent", "object-1", "agent objective"
        )
        self.assertEqual((True, 200), result[:2])

    def test_rejects_wrong_target_or_details(self):
        token = _approval_token("deploy-agent", "object-1", "agent objective", self.secret)
        result = agent_approval.validar_aprobacion_operacion(
            token, "deploy-agent", "object-2", "agent objective"
        )
        self.assertEqual(403, result[1])

    def test_rejects_expired_or_unapproved_tokens(self):
        now = int(time.time())
        expired = _approval_token(
            "deploy-agent", "object-1", "objective", self.secret,
            issued_at=now - 600, expires_at=now - 1,
        )
        unapproved = _approval_token(
            "deploy-agent", "object-1", "objective", self.secret,
            approved_by="outside@example.net",
        )
        for token in (expired, unapproved):
            with self.subTest(token=token[:12]):
                result = agent_approval.validar_aprobacion_operacion(
                    token, "deploy-agent", "object-1", "objective"
                )
                self.assertEqual(403, result[1])

    def test_fails_closed_without_approval_configuration(self):
        with patch.object(agent_approval, "AGENT_APPROVAL_HMAC_SECRET", ""):
            result = agent_approval.validar_aprobacion_operacion("", "deploy-agent", "id", "details")
        self.assertEqual(503, result[1])


class NotificationRecipientTests(unittest.TestCase):
    def test_only_allows_configured_domains(self):
        with patch.object(notifier, "ALLOWED_NOTIFICATION_DOMAINS", ("coem.co",)):
            self.assertTrue(notifier._validar_destinatario("user@coem.co"))
            self.assertFalse(notifier._validar_destinatario("user@example.net"))
            self.assertFalse(notifier._validar_destinatario("user@sub.coem.co"))
            self.assertFalse(notifier._validar_destinatario("user@coem.co\r\nBcc: other@example.net"))


class AgentDeploymentGateTests(unittest.TestCase):
    class Request:
        def get_json(self):
            return {
                "solicitud": "Asistente interno",
                "agentObjectId": "12345678-1234-1234-1234-123456789012",
            }

    def test_denies_deployment_before_graph_when_approval_is_missing(self):
        with patch.object(
            create_agent_module,
            "validar_aprobacion_operacion",
            return_value=(False, 503, "Approval unavailable"),
        ), patch.object(create_agent_module, "get_graph_token") as get_graph_token:
            response = create_agent_module.create_agent(self.Request())

        self.assertEqual(503, response.status_code)
        get_graph_token.assert_not_called()


class PromptReviewTests(unittest.TestCase):
    class Request:
        def __init__(self, body):
            self.body = body

        def get_json(self):
            return self.body

    def test_keyword_clear_prompt_is_not_approved(self):
        response = evaluate_prompt(self.Request({"prompt": "Ayúdame a redactar una agenda."}))
        payload = json.loads(response.get_body())
        self.assertEqual("NEEDS_REVIEW", payload["status"])
        self.assertIsNone(payload["signature"])

    def test_matching_blocked_term_is_rejected(self):
        response = evaluate_prompt(self.Request({"prompt": "Necesito la contraseña."}))
        payload = json.loads(response.get_body())
        self.assertEqual("REJECTED", payload["status"])


class DefenderSnapshotMatchingTests(unittest.TestCase):
    def test_matches_normalized_exact_names_only(self):
        snapshot = {"cafe agent": 82}
        self.assertEqual(82, _score_defender("Café Agent", snapshot))
        self.assertIsNone(_score_defender("agent", snapshot))


class ApplicationPermissionAuditTests(unittest.TestCase):
    class Response:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    class Session:
        def __init__(self, bodies):
            self.bodies = iter(bodies)
            self.urls = []

        def post(self, url, json, timeout):
            self.urls.append(url)
            return ApplicationPermissionAuditTests.Response(next(self.bodies))

    def test_reads_application_assignments_in_graph_batch(self):
        session = self.Session([{
            "responses": [{
                "id": "0",
                "status": 200,
                "body": {"value": [{"id": "assignment-1"}]},
            }]
        }])
        assignments, complete = _fetch_app_role_assignments(
            session, [{"id": "principal-1"}], time.time(), 55
        )
        self.assertTrue(complete)
        self.assertEqual("assignment-1", assignments["principal-1"][0]["id"])
        self.assertEqual("https://graph.microsoft.com/v1.0/$batch", session.urls[0])

    def test_marks_failed_graph_batches_as_incomplete(self):
        session = self.Session([{
            "responses": [{"id": "0", "status": 403, "body": {}}]
        }])
        assignments, complete = _fetch_app_role_assignments(
            session, [{"id": "principal-1"}], time.time(), 55
        )
        self.assertFalse(complete)
        self.assertEqual([], assignments["principal-1"])

    def test_follows_graph_batch_pagination(self):
        session = self.Session([
            {
                "responses": [{
                    "id": "0",
                    "status": 200,
                    "body": {
                        "value": [{"id": "assignment-1"}],
                        "@odata.nextLink": (
                            "https://graph.microsoft.com/v1.0/servicePrincipals/"
                            "principal-1/appRoleAssignments?$skiptoken=next"
                        ),
                    },
                }]
            },
            {
                "responses": [{
                    "id": "0",
                    "status": 200,
                    "body": {"value": [{"id": "assignment-2"}]},
                }]
            },
        ])
        assignments, complete = _fetch_app_role_assignments(
            session, [{"id": "principal-1"}], time.time(), 55
        )
        self.assertTrue(complete)
        self.assertEqual(["assignment-1", "assignment-2"], [
            item["id"] for item in assignments["principal-1"]
        ])
        self.assertEqual(2, len(session.urls))

    def test_inventory_enriches_catalog_packages_with_both_permission_types(self):
        class GraphSession:
            def __init__(self):
                self.urls = []

            def get(self, url, params=None, timeout=None):
                self.urls.append(url)
                if "copilot/admin/catalog/packages" in url:
                    return ApplicationPermissionAuditTests.Response({
                        "value": [{
                            "id": "package-1",
                            "appId": "app-1",
                            "displayName": "Test Agent",
                            "state": "Active",
                            "shortDescription": "Internal AI assistant",
                            "platform": "Copilot Studio",
                            "publisher": "Contoso",
                            "elementTypes": ["CustomEngineAgent"],
                            "agentIdentityId": "agent-identity-1",
                            "isBlocked": False,
                        }]
                    })
                if "/servicePrincipals?" in url:
                    return ApplicationPermissionAuditTests.Response({
                        "value": [{
                            "id": "sp-1",
                            "appId": "app-1",
                            "displayName": "Test Agent",
                            "accountEnabled": True,
                            "publisherName": "Contoso",
                            "verifiedPublisher": {"displayName": "Contoso"},
                            "tags": [],
                        }]
                    })
                if "/applications?" in url:
                    return ApplicationPermissionAuditTests.Response({
                        "value": [{
                            "id": "application-1",
                            "appId": "app-1",
                            "displayName": "Test Agent",
                            "description": "Internal AI assistant",
                            "requiredResourceAccess": [],
                        }]
                    })
                if "oauth2PermissionGrants" in url:
                    return ApplicationPermissionAuditTests.Response({
                        "value": [{
                            "id": "delegated-1",
                            "clientId": "sp-1",
                            "scope": "Mail.Read",
                            "consentType": "AllPrincipals",
                        }]
                    })
                raise AssertionError(f"Unexpected Graph URL: {url}")

            def post(self, url, json, timeout):
                return ApplicationPermissionAuditTests.Response({
                    "responses": [{
                        "id": "0",
                        "status": 200,
                        "body": {"value": [{"id": "app-role-1"}]},
                    }]
                })

        graph_session = GraphSession()
        with patch.object(audit_module, "get_graph_token", return_value="token"), patch.object(
            audit_module, "create_concurrent_session", return_value=graph_session
        ), patch.object(
            audit_module,
            "fetch_azure_ai_resources",
            return_value=([], {"estado": "COMPLETA", "registros": 0, "detalle": ""}),
        ), patch.object(
            audit_module,
            "fetch_defender_cloud_apps",
            return_value=([], {"estado": "COMPLETA", "registros": 0, "detalle": ""}),
        ):
            result = ejecutar_inventario_concurrente()

        self.assertNotIn("error", result)
        self.assertEqual(1, len(result["agentes"]))
        self.assertIn(
            "https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages",
            graph_session.urls,
        )
        self.assertEqual("Delegado y aplicación", result["agentes"][0]["tipoPermiso"])
        self.assertTrue(result["agentes"][0]["registroAplicacion"])
        self.assertEqual("AGENTE", result["agentes"][0]["tipoInventario"])
        self.assertEqual("agent-identity-1", result["agentes"][0]["agentIdentityId"])
        self.assertEqual("Copilot Studio", result["agentes"][0]["plataforma"])
        self.assertEqual("ALTA", result["agentes"][0]["confianzaDeteccion"])
        self.assertEqual("COMPLETA", result["fuentes"]["appRoleAssignments"]["estado"])

    def test_inventory_remains_available_when_agent365_catalog_is_unlicensed(self):
        class GraphSession:
            def get(self, url, params=None, timeout=None):
                if "copilot/admin/catalog/packages" in url:
                    response = ApplicationPermissionAuditTests.Response({"error": "forbidden"})
                    response.status_code = 403
                    return response
                return ApplicationPermissionAuditTests.Response({"value": []})

        with patch.object(audit_module, "get_graph_token", return_value="token"), patch.object(
            audit_module, "create_concurrent_session", return_value=GraphSession()
        ), patch.object(
            audit_module,
            "fetch_azure_ai_resources",
            return_value=([], {"estado": "COMPLETA", "registros": 0, "detalle": ""}),
        ), patch.object(
            audit_module,
            "fetch_defender_cloud_apps",
            return_value=([], {"estado": "COMPLETA", "registros": 0, "detalle": ""}),
        ):
            result = ejecutar_inventario_concurrente()

        self.assertNotIn("error", result)
        self.assertEqual("PARCIAL", result["estadoCobertura"])
        self.assertEqual("PARCIAL", result["fuentes"]["agent365PackageManagement"]["estado"])
        self.assertIn("CopilotPackages.Read.All",
                      result["fuentes"]["agent365PackageManagement"]["detalle"])

    def test_ai_classifier_marks_low_confidence_agent_names(self):
        classified = _marcar_clasificacion_ia({
            "nombre": "Travel Agent",
            "plataforma": "Entra ID App Registration",
            "descripcion": "",
            "tipoRecurso": "",
        })
        self.assertTrue(classified["esPosibleIA"])
        self.assertEqual("BAJA (nombre o descripción)", classified["confianzaDeteccion"])


class EnterpriseSourceTests(unittest.TestCase):
    class Response:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self.body = body

        def json(self):
            return self.body

    class AzureSession:
        def __init__(self):
            self.requests = []

        def post(self, url, json, timeout):
            self.requests.append(json)
            if len(self.requests) == 1:
                return EnterpriseSourceTests.Response(200, {
                    "data": [{"id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai1",
                              "name": "ai1", "type": "microsoft.cognitiveservices/accounts",
                              "subscriptionId": "s1", "resourceGroup": "rg", "location": "eastus"}],
                    "$skipToken": "next-page",
                })
            return EnterpriseSourceTests.Response(200, {"data": [], "resultTruncated": False})

    def test_azure_resource_graph_follows_skip_token(self):
        session = self.AzureSession()
        with patch.object(enterprise_sources, "AZURE_SUBSCRIPTION_IDS", ("s1",)), patch.object(
            enterprise_sources, "AZURE_MANAGEMENT_GROUP_IDS", ()
        ), patch.object(
            enterprise_sources, "get_scoped_token", return_value="token"
        ), patch.object(enterprise_sources, "create_concurrent_session", return_value=session):
            resources, status = enterprise_sources.fetch_azure_ai_resources()

        self.assertEqual(1, len(resources))
        self.assertEqual("COMPLETA", status["estado"])
        self.assertEqual("next-page", session.requests[1]["options"]["$skipToken"])
        self.assertEqual("Azure AI Services / Azure OpenAI",
                         enterprise_sources.map_azure_resource_to_inventory(resources[0])["plataforma"])

    def test_marks_truncated_resource_graph_results_incomplete(self):
        class TruncatedSession:
            def post(self, url, json, timeout):
                return EnterpriseSourceTests.Response(200, {
                    "data": [],
                    "resultTruncated": True,
                })

        with patch.object(enterprise_sources, "AZURE_SUBSCRIPTION_IDS", ("s1",)), patch.object(
            enterprise_sources, "AZURE_MANAGEMENT_GROUP_IDS", ()
        ), patch.object(
            enterprise_sources, "get_scoped_token", return_value="token"
        ), patch.object(
            enterprise_sources, "create_concurrent_session", return_value=TruncatedSession()
        ):
            _, status = enterprise_sources.fetch_azure_ai_resources()

        self.assertEqual("ERROR", status["estado"])
        self.assertIn("truncó resultados", status["detalle"])

    def test_defender_cloud_app_search_uses_graph_hunting_query(self):
        class DefenderSession:
            def post(self, url, json, timeout):
                self.url = url
                self.query = json["Query"]
                return EnterpriseSourceTests.Response(200, {
                    "results": [{
                        "Application": "Example AI Assistant",
                        "EventCount": 17,
                        "UserCount": 4,
                        "LastSeen": "2026-11-25T10:00:00Z",
                    }]
                })

        session = DefenderSession()
        results, status = enterprise_sources.fetch_defender_cloud_apps(session)
        item = enterprise_sources.map_defender_app_to_inventory(results[0])
        self.assertEqual("https://graph.microsoft.com/v1.0/security/runHuntingQuery", session.url)
        self.assertIn("CloudAppEvents", session.query)
        self.assertEqual("COMPLETA", status["estado"])
        self.assertEqual(17, item["eventosObservados"])


class AuditEndpointTests(unittest.TestCase):
    class Request:
        method = "POST"
        params = {}

        def get_json(self):
            return {
                "filter": "ia",
                "search": "assistant",
                "limit": 25,
                "offset": 50,
            }

    def test_passes_filter_search_and_pagination_to_inventory(self):
        response_body = {
            "agentes": [{"nombre": "AI assistant", "plataforma": "Entra ID",
                         "esPosibleIA": True, "puntuacionRiesgo": 80,
                         "nivelRiesgo": "ALTO", "origen": "Entra ID",
                         "id": "app-1"}],
            "metricasGlobales": {
                "totalAplicaciones": 10,
                "totalAgentesRegistrados": 5,
                "posiblesAgentesIA": 4,
                "agentesEnRiesgo": 2,
                "aplicacionesCloudObservadas": 0,
                "recursosAzureIA": 0,
            },
            "fuentes": {
                "appRoleAssignments": {"estado": "COMPLETA", "registros": 0},
            },
            "estadoCobertura": "PARCIAL",
            "metricasAgentMap": {},
            "totalFiltrados": 80,
            "tiempoRespuestaSegundos": 1.2,
        }
        with patch.object(
            audit_endpoint,
            "ejecutar_inventario_concurrente",
            return_value=response_body,
        ) as inventory:
            response = audit_endpoint.get_full_audit(self.Request())

        inventory.assert_called_once_with(
            filtro="ia", search_term="assistant", limit=25, offset=50
        )
        self.assertEqual(200, response.status_code)
        payload = json.loads(response.get_body())
        self.assertTrue(payload["tieneMasResultados"])
        self.assertEqual(80, payload["totalFiltrados"])


if __name__ == "__main__":
    unittest.main()
