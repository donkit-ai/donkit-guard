"""Generate or verify the OpenAPI document of the analyze contract.

A remote detector asks a service for findings with ``POST /v1/analyze``. The request and the
answer are the pydantic models in ``donkit_guard.adapters``, which are the single source of truth
for the contract. This script renders them, with the two operations around them, as an OpenAPI 3.1
document that implementers and tooling can read. The committed file is derived data: CI runs
``--check`` so it cannot drift from the models.

    poetry run python scripts/gen_contract.py --write   # regenerate the committed file
    poetry run python scripts/gen_contract.py --check   # exit 1 when the committed file differs
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic.json_schema import models_json_schema

from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSegment, AnalyzeSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_FILE = ROOT / "docs" / "contract" / "analyze-v1.openapi.json"
REGENERATE = "poetry run python scripts/gen_contract.py --write"

MODELS = (AnalyzeRequest, AnalyzeSegment, AnalyzeResponse, AnalyzeSpan)
REF_TEMPLATE = "#/components/schemas/{model}"

INFO_DESCRIPTION = (
    "What a service that finds entities in text answers to a remote detector. Anyone can "
    "implement it and point a policy document at it. Generated from the models in "
    "donkit_guard.adapters by scripts/gen_contract.py: change the models, not this file."
)
ANALYZE_DESCRIPTION = (
    "Finds entities in each segment of the request and reports each as a span. Offsets count "
    "Unicode code points into the text of the segment the span names, as a Python `str` index "
    "does, and `end` is exclusive. A service that cannot answer within `deadline_ms` answers "
    "`failed: true` with a short `error` instead of keeping the caller waiting, and never "
    "passes an empty `spans` off as a clean result; the spans of a failed answer are ignored. "
    "A field the service adds to its answer beyond those listed is ignored."
)
HEALTHZ_DESCRIPTION = (
    "Optional. A service may expose it so that orchestrators and operators can see that it is "
    "up. The analyze contract does not depend on it, and its body is not specified."
)


def _ref(model: str) -> dict[str, str]:
    return {"$ref": REF_TEMPLATE.format(model=model)}


def build_document() -> dict[str, Any]:
    """The OpenAPI document: the two operations and the schemas of the contract's models."""
    _, schemas = models_json_schema(
        [(model, "validation") for model in MODELS], ref_template=REF_TEMPLATE
    )
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "donkit-guard analyze contract",
            "version": "1",
            "description": INFO_DESCRIPTION,
        },
        "paths": {
            "/v1/analyze": {
                "post": {
                    "operationId": "analyze",
                    "summary": "Find entities in text",
                    "description": ANALYZE_DESCRIPTION,
                    "security": [{}, {"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": _ref("AnalyzeRequest")}},
                    },
                    "responses": {
                        "200": {
                            "description": (
                                "The segments were analyzed, or the service reports with "
                                "`failed: true` that it could not analyze them."
                            ),
                            "content": {"application/json": {"schema": _ref("AnalyzeResponse")}},
                        },
                        "default": {
                            "description": (
                                "Any other status. The caller treats the call as failed and "
                                "does not read the body."
                            ),
                        },
                    },
                },
            },
            "/healthz": {
                "get": {
                    "operationId": "healthz",
                    "summary": "Check that the service is up (optional)",
                    "description": HEALTHZ_DESCRIPTION,
                    "responses": {
                        "200": {"description": "The service is up. The body can be anything."},
                    },
                },
            },
        },
        "components": {
            "schemas": schemas["$defs"],
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "Optional. A service that requires a token expects it as "
                        "`Authorization: Bearer <token>`."
                    ),
                },
            },
        },
    }


def render() -> str:
    """The text of the committed file: stable key order, two-space indent, final newline."""
    document = build_document()
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the OpenAPI document of the analyze contract."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if the file is out of date")
    mode.add_argument("--write", action="store_true", help="regenerate the committed file")
    args = parser.parse_args(argv)

    expected = render()
    shown = CONTRACT_FILE.relative_to(ROOT)
    if args.write:
        CONTRACT_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONTRACT_FILE.write_text(expected, encoding="utf-8", newline="\n")
        print(f"wrote {shown}")
        return 0
    try:
        committed = CONTRACT_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"{shown} is missing; run: {REGENERATE}", file=sys.stderr)
        return 1
    if committed != expected:
        print(f"{shown} is out of date with the models; run: {REGENERATE}", file=sys.stderr)
        return 1
    print(f"{shown} is up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
