"""Normalise Mend API 3.0 payloads into the shapes reconciliation consumes.

Pure module -- no I/O, no globals, no Config. All HTTP lives in core.py. Same split as
routing.py and enrichment.py.

This separation is deliberate and load-bearing beyond tidiness: the spec shelves a future 1.4
compatibility path for customers not yet on 3.0. Reconciliation consumes the normalised shapes
defined here and must never reach into a 3.0 response, so that path is a second producer rather
than a rewrite.
"""

import os
import sys

sys.path.append(os.path.dirname(__file__))

# CVSS v3 band floors. A band names the BOTTOM of its range, so "high" selects 7.0 and up.
_BANDS = {"low": 0.1, "medium": 4.0, "high": 7.0, "critical": 9.0}

DEFAULT_FLOOR = 7.0


def severity_floor(raw) -> float:
    """MEND_SEVERITY -> the minimum CVSS score that earns a work item.

    Anything unparseable falls back to DEFAULT_FLOOR rather than to 0. A typo must not silently
    turn a high-severity filter into "every finding in the org", which at this customer's scale
    is tens of thousands of work items.
    """
    text = str(raw or "").strip().lower()
    if not text:
        return DEFAULT_FLOOR
    if text in _BANDS:
        return _BANDS[text]
    try:
        value = float(text)
    except (TypeError, ValueError):
        return DEFAULT_FLOOR
    return value if 0.0 <= value <= 10.0 else DEFAULT_FLOOR


def meets_threshold(score, floor: float) -> bool:
    """Is this finding severe enough to hold a work item open?

    An UNSCORED finding is included, deliberately (spec 5.1): it cannot be compared, and a real
    vulnerability disappearing because Mend has not scored it yet is worse than one extra work
    item. `None` and "" mean unscored; 0.0 is a real score and is compared normally.
    """
    if score is None or score == "":
        return True
    try:
        return float(score) >= floor
    except (TypeError, ValueError):
        # A score we cannot read is not a score that lets us exclude anything.
        return True


# The ONLY status that holds a work item open. Every other value in
# SecurityFindingDTOV3.findingInfo.status -- IGNORED (suppressed in Mend), LIBRARY_REMOVED,
# LIBRARY_IN_HOUSE, LIBRARY_WHITELIST -- means the work item should be closed.
#
# This single field is why v3 can close work items and 1.4 never could: 1.4 published no status,
# so closure there had to be inferred from a finding's ABSENCE, and absence is indistinguishable
# from a failed read.
OPEN_STATUS = "ACTIVE"


def _walk(obj, *path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def normalise_findings(findings, floor: float):
    """3.0 security findings -> ({library_name: entry}, unscored_count).

    Only ACTIVE findings at or above `floor` survive. findingInfo.findingStatus is deliberately
    NOT consulted -- see OPEN_STATUS.

    A library whose findings are all excluded produces NO entry, which is what tells
    reconciliation to close its work item. An entry with an empty findings list would keep the
    item open forever, so entries are only created when something survives.
    """
    entries = {}
    unscored = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        if _walk(finding, "findingInfo", "status") != OPEN_STATUS:
            continue
        lib = _walk(finding, "component", "name")
        if not lib:
            continue
        score = _walk(finding, "vulnerability", "score")
        if not meets_threshold(score, floor):
            continue
        if score is None or score == "":
            unscored += 1
        entry = entries.setdefault(lib, {"library": lib, "kind": "vulnerability", "findings": []})
        entry["findings"].append(finding)
    return entries, unscored
