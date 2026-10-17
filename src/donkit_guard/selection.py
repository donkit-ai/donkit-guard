"""Which detectors an evaluation runs, and whether its decision waits for them.

A detector runs synchronously when a rule that decides the outcome (any action but `audit`)
could use its findings, in the background when only `audit` rules could, and not at all
otherwise. Whether a rule could use a detector's findings is judged from what is known
before a scan: the classes the detector reports and, when it declares them, its subtypes.
Every doubt resolves towards running the detector: one left out silently weakens a
decision, while one run needlessly only costs time.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import TYPE_CHECKING

from donkit_guard.detectors.base import AnyDetector, detector_subtypes
from donkit_guard.policy import RuleAction

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.policy import Match, Rule


@dataclass(frozen=True)
class DetectorSelection:
    """The detectors one evaluation runs.

    The decision waits for the findings of `sync`. The findings of `background` feed
    `audit` rules only, so they are recorded after the decision.
    """

    sync: tuple[AnyDetector, ...] = ()
    background: tuple[AnyDetector, ...] = ()


def could_use(match: Match, detector: AnyDetector) -> bool:
    """Whether a span the detector reports could satisfy the finding selectors of `match`.

    Only the class and subtype selectors can rule a detector out, read the way
    `Match.matches_span` reads them; a detector that does not declare its subtypes may
    report any. `min_score` and `segment_trust` depend on the span itself, so they never do.
    """
    if match.finding_class is not None and not any(
        wanted in detector.classes for wanted in match.finding_class
    ):
        return False
    if match.finding_subtype is not None:
        subtypes = detector_subtypes(detector)
        if subtypes is not None and not any(
            fnmatch.fnmatchcase(subtype, pattern)
            for subtype in subtypes
            for pattern in match.finding_subtype
        ):
            return False
    return True


def select_detectors(
    finding_rules: Sequence[Rule], detectors: Sequence[AnyDetector]
) -> DetectorSelection:
    """Split `detectors` by the rules that could use their findings.

    `finding_rules` are the rules that matched the context and select findings. A detector
    is synchronous when a rule with any action but `audit` could use it, runs in the
    background when only `audit` rules could, and is left out otherwise. Both tuples keep
    the order of `detectors`, and a detector passed more than once is selected once.
    """
    enforcing = [rule.match for rule in finding_rules if rule.action is not RuleAction.AUDIT]
    auditing = [rule.match for rule in finding_rules if rule.action is RuleAction.AUDIT]
    sync: list[AnyDetector] = []
    background: list[AnyDetector] = []
    seen: set[int] = set()
    for detector in detectors:
        if id(detector) in seen:
            continue
        seen.add(id(detector))
        if any(could_use(match, detector) for match in enforcing):
            sync.append(detector)
        elif any(could_use(match, detector) for match in auditing):
            background.append(detector)
    return DetectorSelection(sync=tuple(sync), background=tuple(background))
