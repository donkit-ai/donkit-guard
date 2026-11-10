"""Counters of the service, rendered in the Prometheus text format at ``GET /metrics``."""

from __future__ import annotations

import threading
from collections import Counter
from enum import StrEnum


class Metric(StrEnum):
    DECISIONS = "guard_decisions_total"
    POLICY_RELOADS = "guard_policy_reloads_total"
    POLICY_RELOAD_FAILURES = "guard_policy_reload_failures_total"
    GATEWAY_ERRORS = "guard_gateway_errors_total"
    APPROVALS_EXPIRED = "guard_approvals_expired_total"


_HELP: dict[Metric, str] = {
    Metric.DECISIONS: "Decisions returned, by surface and outcome.",
    Metric.POLICY_RELOADS: "Policy files loaded and applied.",
    Metric.POLICY_RELOAD_FAILURES: "Policy files refused; the previous version stays active.",
    Metric.GATEWAY_ERRORS: "Gateway exchanges the guard failed to process, answered fail-closed.",
    Metric.APPROVALS_EXPIRED: "Pending approvals that expired without a decision.",
}

Labels = tuple[tuple[str, str], ...]


class Metrics:
    """Monotonic counters with optional labels; safe to bump from any thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: Counter[tuple[Metric, Labels]] = Counter()

    def inc(self, metric: Metric, amount: int = 1, **labels: str) -> None:
        key = (metric, tuple(sorted(labels.items())))
        with self._lock:
            self._values[key] += amount

    def value(self, metric: Metric, **labels: str) -> int:
        with self._lock:
            return self._values[(metric, tuple(sorted(labels.items())))]

    def render(self) -> str:
        with self._lock:
            values = dict(self._values)
        lines: list[str] = []
        for metric in Metric:
            lines.append(f"# HELP {metric.value} {_HELP[metric]}")
            lines.append(f"# TYPE {metric.value} counter")
            series = [(labels, v) for (m, labels), v in values.items() if m is metric]
            if not series:
                lines.append(f"{metric.value} 0")
            for labels, value in sorted(series):
                rendered = ",".join(f'{k}="{v}"' for k, v in labels)
                name = f"{metric.value}{{{rendered}}}" if rendered else metric.value
                lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"
