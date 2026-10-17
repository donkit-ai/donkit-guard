"""RE2 for declared pattern detectors, behind an optional dependency.

Patterns come from policy documents, so they run on RE2, which matches in time linear in the
text: no pattern can be written that stalls the process. RE2 has no lookaround and no
backreferences, and its word boundary knows ASCII word characters only. Terms detectors take
no expressions and match without RE2.

``google-re2`` is the ``re2`` extra. This is the only module that imports it, and importing
this module never fails: a missing package is reported when a pattern is compiled.
"""

from __future__ import annotations

from typing import Any

try:
    import re2

    _INSTALLED = True
except ImportError:  # the optional "re2" extra is not installed
    _INSTALLED = False

RE2_MISSING = "pattern detectors need the 're2' extra: pip install 'donkit-guard[re2]'"


def re2_available() -> bool:
    return _INSTALLED


def compile_re2(pattern: str) -> Any:
    """Compile ``pattern`` with RE2.

    Raises ``ValueError`` carrying RE2's own reason for a pattern it refuses (lookaround, a
    backreference, bad syntax) and ``RuntimeError`` when ``google-re2`` is not installed.
    """
    if not _INSTALLED:
        raise RuntimeError(RE2_MISSING)
    # RE2 writes parse errors to stderr unless told not to; the reason is raised instead.
    options = re2.Options()
    options.log_errors = False
    try:
        return re2.compile(pattern, options)
    except re2.error as exc:
        raise ValueError(_reason(exc)) from exc


def _reason(exc: Exception) -> str:
    # google-re2 hands RE2's reason over as UTF-8 bytes, which ``str`` would show as a bytes
    # literal in a policy error.
    reason = exc.args[0] if exc.args else ""
    return reason.decode("utf-8", errors="replace") if isinstance(reason, bytes) else str(reason)
