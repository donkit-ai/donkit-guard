"""The ExtMcp server of the MCP route: ``tools/call`` checked before the tool runs and after.

A call the policy refuses never reaches the MCP server: the client receives JSON-RPC error
``-32001`` with the reason. A call that needs an approval is refused the same way with
``status: approval_pending`` and the ``approval_id``; once the principal approved it through
the admin API, the client repeats the same call in the same session and it runs, once. A call
whose maskable arguments carry findings goes on with those arguments masked, the shape of the
arguments unchanged. The result of a call is checked as a tool result: masked or refused.

Any failure inside the guard refuses the call.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from google.protobuf import json_format

from donkit_guard.context import Action, ActionKind, GuardContext
from donkit_guard.decision import Decision, Outcome
from donkit_guard.payload import Payload, SegmentSource, SegmentTrust, set_json_pointer
from donkit_guard_standalone.identity import GatewayIdentity, IdentityMissing, identity_from
from donkit_guard_standalone.metrics import Metric
from donkit_guard_standalone.proto import ext_mcp_pb2 as pb

if TYPE_CHECKING:
    import grpc

    from donkit_guard_standalone.service import GuardService

logger = logging.getLogger("donkit_guard_standalone.extmcp")

TOOLS_CALL = "tools/call"
# agentgateway answers a refused call with a JSON-RPC error whose code it derives from
# AuthorizationError.code (PERMISSION_DENIED is -32001), whose message is `reason`, and whose `data`
# is the JSON in `mcp_error`. Every refusal uses PERMISSION_DENIED, so the client sees one code.
SERVICE_ATTRIBUTE = "mcp_service"


class _Refused(Exception):
    def __init__(self, reason: str, data: dict[str, Any]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.data = data


def _passed_request() -> pb.McpRequestResult:
    result = pb.McpRequestResult()
    getattr(result, "pass").SetInParent()  # `pass` is a Python keyword
    return result


def _passed_response() -> pb.McpResponseResult:
    result = pb.McpResponseResult()
    getattr(result, "pass").SetInParent()
    return result


def _identity(metadata: Any, headers: Any) -> GatewayIdentity:
    attributes = json_format.MessageToDict(metadata) if metadata is not None else {}
    header_map = {h.key.lower(): h.value.decode("utf-8", "replace") for h in headers}
    return identity_from(attributes, header_map)


def _error(reason: str, data: dict[str, Any]) -> pb.AuthorizationError:
    return pb.AuthorizationError(
        code=pb.AuthorizationError.PERMISSION_DENIED,
        reason=reason,
        mcp_error=json.dumps(data, ensure_ascii=False).encode(),
    )


def _refusal(decision: Decision) -> _Refused:
    explanation = decision.explanation
    data: dict[str, Any] = {
        "status": "denied",
        "code": explanation.code,
        "decision_id": decision.decision_id,
    }
    if decision.outcome is Outcome.APPROVAL_PENDING and decision.approval is not None:
        data.update(
            status="approval_pending",
            approval_id=decision.approval.approval_id,
            expires_at=decision.approval.expires_at.isoformat(),
        )
        return _Refused(f"approval required: {explanation.reason}", data)
    return _Refused(explanation.reason or "blocked by policy", data)


def _masked(payload: Payload, value: Any, masks: dict[str, str]) -> Any:
    for segment in payload.segments:
        if segment.id in masks:
            value = set_json_pointer(value, segment.path, masks[segment.id])
    return value


class McpPolicy:
    """The `agentgateway.dev.ext_mcp.ExtMcp` service."""

    def __init__(self, service: GuardService) -> None:
        self._service = service

    async def CheckRequest(
        self,
        request: pb.McpRequest,
        context: grpc.aio.ServicerContext[pb.McpRequest, pb.McpRequestResult],
    ) -> pb.McpRequestResult:
        if request.method != TOOLS_CALL:
            return _passed_request()
        try:
            return await self._check_call(request)
        except _Refused as refused:
            return pb.McpRequestResult(error=_error(refused.reason, refused.data))
        except IdentityMissing as exc:
            return pb.McpRequestResult(error=_error(str(exc), {"status": "unauthenticated"}))
        except Exception:  # fail closed: a guard failure never lets a tool call through
            logger.exception("ExtMcp failed on %s", request.method)
            self._service.metrics.inc(Metric.GATEWAY_ERRORS, surface="mcp")
            reason = "the guard could not check this call"
            return pb.McpRequestResult(error=_error(reason, {"status": "guard_error"}))

    async def CheckResponse(
        self,
        request: pb.McpResponse,
        context: grpc.aio.ServicerContext[pb.McpResponse, pb.McpResponseResult],
    ) -> pb.McpResponseResult:
        if request.method != TOOLS_CALL:
            return _passed_response()
        try:
            return await self._check_result(request)
        except _Refused as refused:
            return pb.McpResponseResult(error=_error(refused.reason, refused.data))
        except Exception:  # fail closed: an unchecked result is not returned
            logger.exception("ExtMcp failed on the result of %s", request.method)
            self._service.metrics.inc(Metric.GATEWAY_ERRORS, surface="mcp")
            reason = "the guard could not check this result"
            return pb.McpResponseResult(error=_error(reason, {"status": "guard_error"}))

    async def _check_call(self, request: pb.McpRequest) -> pb.McpRequestResult:
        identity = _identity(request.metadata_context, request.headers)
        params = json.loads(request.mcp_request) if request.HasField("mcp_request") else {}
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise _Refused("tools/call needs a tool name", {"status": "invalid"})
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise _Refused("tools/call arguments must be an object", {"status": "invalid"})
        ctx = GuardContext(
            principal=identity.principal_ref(),
            tenant=identity.tenant_ref(),
            agent=identity.agent_ref(),
            run=identity.run_ref("mcp"),
            action=Action(kind=ActionKind.TOOL_CALL, tool=params["name"], arguments=arguments),
            attributes=self._attributes(request),
        )
        payload = Payload.from_json(
            arguments, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED
        )
        decision = await self._service.authorize(ctx, payload, surface="mcp_request")
        if not decision.is_allowed():
            raise _refusal(decision)
        if decision.outcome is Outcome.MASK and decision.masked_segments:
            masked = dict(params, arguments=_masked(payload, arguments, decision.masked_segments))
            return pb.McpRequestResult(mutated=json.dumps(masked, ensure_ascii=False).encode())
        return _passed_request()

    async def _check_result(self, request: pb.McpResponse) -> pb.McpResponseResult:
        identity = _identity(request.metadata_context, ())
        result = json.loads(request.mcp_response) if request.mcp_response else {}
        if not isinstance(result, dict):
            return _passed_response()
        payload = Payload.from_json(
            {key: result[key] for key in ("content", "structuredContent") if key in result},
            source=SegmentSource.TOOL_RESULT,
            trust=SegmentTrust.UNTRUSTED,
        )
        service = request.service_names[0] if request.service_names else "mcp"
        ctx = GuardContext(
            principal=identity.principal_ref(),
            tenant=identity.tenant_ref(),
            agent=identity.agent_ref(),
            run=identity.run_ref("mcp", untrusted_content_seen=True),
            # The result does not name its tool; the MCP service stands in for it.
            action=Action(kind=ActionKind.TOOL_RESULT, tool=service),
            attributes=self._attributes(request),
        )
        decision = await self._service.authorize(ctx, payload, surface="mcp_response")
        if not decision.is_allowed():
            raise _refusal(decision)
        if decision.outcome is Outcome.MASK and decision.masked_segments:
            masked = _masked(payload, result, decision.masked_segments)
            return pb.McpResponseResult(mutated=json.dumps(masked, ensure_ascii=False).encode())
        return _passed_response()

    @staticmethod
    def _attributes(request: pb.McpRequest | pb.McpResponse) -> dict[str, str | int | bool]:
        if request.service_names:
            return {SERVICE_ATTRIBUTE: request.service_names[0]}
        return {}
