"""The HTTP API over SQLite: decisions, approvals, audit, policy reloads and probes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from donkit_guard_standalone.metrics import Metric

from .conftest import ACME, ADMIN, GLOBEX, SECRET

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from donkit_guard_standalone.settings import Settings

    from .conftest import Running

pytestmark = pytest.mark.asyncio


def _llm_context(**extra: Any) -> dict[str, Any]:
    return {
        "principal": {"id": "user-1", "kind": "user", "approver": True},
        "run": {"id": "run-1"},
        "action": {"kind": "llm_request"},
        **extra,
    }


def _tool_context(tool: str, arguments: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "principal": {"id": "user-1", "kind": "user", "approver": True},
        "run": {"id": "run-1"},
        "action": {"kind": "tool_call", "tool": tool, "arguments": arguments},
        **extra,
    }


async def _authorize(running: Running, body: dict[str, Any], headers: dict[str, str] = ACME) -> Any:
    response = await running.client.post("/v1/authorize", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


async def test_secret_in_a_message_is_masked(running: Running) -> None:
    answer = await _authorize(
        running,
        {
            "context": _llm_context(),
            "payload": [{"source": "user", "trust": "trusted", "text": f"deploy with {SECRET}"}],
        },
    )
    assert answer["decision"]["outcome"] == "mask"
    (item,) = answer["masked_payload"]
    assert SECRET not in item["text"] and item["text"].startswith("deploy with [REDACTED:")


async def test_write_tool_call_is_approved_once_by_its_principal(running: Running) -> None:
    body = {"context": _tool_context("create_ticket", {"title": "Refund", "description": "ok"})}
    pending = (await _authorize(running, body))["decision"]
    assert pending["outcome"] == "approval_pending"
    approval_id = pending["approval"]["approval_id"]

    listed = await running.client.get("/admin/approvals", headers=ADMIN)
    assert [a["id"] for a in listed.json()["items"]] == [approval_id]
    stranger = await running.client.post(
        f"/admin/approvals/{approval_id}/decide",
        json={"decision": "approve", "responder": "someone-else"},
        headers=ADMIN,
    )
    assert stranger.status_code == 403 and stranger.json()["error"] == "responder_mismatch"
    decided = await running.client.post(
        f"/admin/approvals/{approval_id}/decide",
        json={"decision": "approve", "responder": "user-1"},
        headers=ADMIN,
    )
    assert decided.status_code == 200 and decided.json()["status"] == "approved"

    executed = (await _authorize(running, body))["decision"]
    assert executed["outcome"] == "allow" and executed["explanation"]["code"] == "approved"
    again = (await _authorize(running, body))["decision"]
    assert again["outcome"] == "approval_pending"
    assert again["approval"]["approval_id"] != approval_id


async def test_rejected_approval_denies_the_retry(running: Running) -> None:
    body = {"context": _tool_context("create_ticket", {"title": "Refund"})}
    approval_id = (await _authorize(running, body))["decision"]["approval"]["approval_id"]
    await running.client.post(
        f"/admin/approvals/{approval_id}/decide",
        json={"decision": "reject", "responder": "user-1"},
        headers=ADMIN,
    )
    retry = (await _authorize(running, body))["decision"]
    assert retry["outcome"] == "deny" and retry["explanation"]["code"] == "approval_rejected"
    late = await running.client.post(
        f"/admin/approvals/{approval_id}/decide",
        json={"decision": "approve", "responder": "user-1"},
        headers=ADMIN,
    )
    assert late.status_code == 409


async def test_approval_card_hides_secrets_and_destructive_tools_are_denied(
    running: Running,
) -> None:
    email = await _authorize(
        running,
        {
            "context": _tool_context(
                "send_email",
                {"to": "ops@example.com", "subject": "keys", "body": f"use {SECRET}"},
            )
        },
    )
    # The tool is egress, so it waits for an approval; the card shows no secret.
    decision = email["decision"]
    assert decision["outcome"] == "approval_pending"
    assert SECRET not in str(decision["display_args_redacted"])
    denied = await _authorize(running, {"context": _tool_context("delete_file", {"path": "/"})})
    assert denied["decision"]["outcome"] == "deny"
    assert "tools-destructive-deny" in denied["decision"]["explanation"]["rule_ids"]


@pytest.mark.parametrize(
    ("headers", "tenant", "status"),
    [
        ({}, None, 401),
        ({"X-API-Key": "nope"}, None, 401),
        (ACME, {"id": "globex"}, 403),
        (ACME, {"id": "acme"}, 200),
    ],
)
async def test_client_authentication_binds_the_tenant(
    running: Running, headers: dict[str, str], tenant: dict[str, str] | None, status: int
) -> None:
    context = _llm_context(**({"tenant": tenant} if tenant else {}))
    response = await running.client.post(
        "/v1/authorize", json={"context": context}, headers=headers
    )
    assert response.status_code == status


async def test_admin_api_needs_the_token(running: Running) -> None:
    for headers in ({}, {"Authorization": "Bearer wrong-token-of-some-length"}):
        assert (await running.client.get("/admin/decisions", headers=headers)).status_code == 401


async def test_executions_and_decisions_are_scoped_and_paged(running: Running) -> None:
    ids = []
    for index in range(3):
        body = {"context": _llm_context(run={"id": f"run-{index}"})}
        ids.append((await _authorize(running, body))["decision"]["decision_id"])
    recorded = await running.client.post(
        "/v1/executions", json={"decision_id": ids[0], "outcome": "success"}, headers=ACME
    )
    assert recorded.status_code == 200
    foreign = await running.client.post(
        "/v1/executions", json={"decision_id": ids[1], "outcome": "error"}, headers=GLOBEX
    )
    assert foreign.status_code == 404

    first = (await running.client.get("/admin/decisions?limit=2", headers=ADMIN)).json()
    assert [d["decision_id"] for d in first["items"]] == [ids[2], ids[1]]
    second = (
        await running.client.get(
            f"/admin/decisions?limit=2&before={first['next_cursor']}", headers=ADMIN
        )
    ).json()
    assert [d["decision_id"] for d in second["items"]] == [ids[0]]
    assert second["next_cursor"] is None
    assert second["items"][0]["execution"]["outcome"] == "success"
    by_run = (await running.client.get("/admin/decisions?run_id=run-1", headers=ADMIN)).json()
    assert [d["decision_id"] for d in by_run["items"]] == [ids[1]]


async def test_an_invalid_policy_file_keeps_the_active_version(
    running: Running, policy_file: Path
) -> None:
    before = (await running.client.get("/admin/policy", headers=ADMIN)).json()
    policy_file.write_text("version: broken\nlayers: [{name: x, rules: [{id: r}]}]\n")
    refused = await running.client.post("/admin/policy/reload", headers=ADMIN)
    assert refused.status_code == 422 and refused.json()["version"] == before["version"]
    still = await _authorize(running, {"context": _tool_context("delete_file", {"path": "/"})})
    assert still["decision"]["policy_version"] == before["version"]
    assert running.service.metrics.value(Metric.POLICY_RELOAD_FAILURES) == 1

    policy_file.write_text(
        "version: open\nmode: enforce\nlayers: [{name: x, rules: "
        "[{id: all, match: {action_kind: [tool_call]}, action: allow}]}]\n"
    )
    # Picked up on the next decision, without a reload call.
    opened = await _authorize(running, {"context": _tool_context("delete_file", {"path": "/"})})
    assert opened["decision"]["outcome"] == "allow"
    assert opened["decision"]["policy_version"].startswith("open@")
    view = (await running.client.get("/admin/policy", headers=ADMIN)).json()
    assert view["document_version"] == "open" and view["last_error"] is None


async def test_unreachable_pii_service_fails_closed(
    start: Callable[[Settings], Any], make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(pii_disabled=False, pii_url="http://127.0.0.1:9")
    async with start(settings) as running:
        answer = await _authorize(
            running,
            {
                "context": _llm_context(
                    action={
                        "kind": "llm_request",
                        "destination": {"provider": "openai", "model": "gpt", "trust": "unknown"},
                    }
                ),
                "payload": [{"source": "user", "text": "Call John Smith tomorrow"}],
            },
        )
        assert answer["decision"]["outcome"] == "deny"
        assert answer["decision"]["explanation"]["code"] == "detector_unavailable"
        ready = await running.client.get("/readyz")
        assert ready.status_code == 503 and ready.json()["pii"]["ok"] is False


async def test_probes_and_body_limit(running: Running) -> None:
    assert (await running.client.get("/healthz")).status_code == 200
    ready = await running.client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["ready"] is True
    huge = {"context": _llm_context(), "payload": [{"source": "user", "text": "x" * 70_000}]}
    response = await running.client.post("/v1/authorize", json=huge, headers=ACME)
    assert response.status_code == 413
    metrics = (await running.client.get("/metrics")).text
    assert "guard_policy_reloads_total 1" in metrics
