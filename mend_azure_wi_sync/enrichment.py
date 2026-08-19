import os
import sys

sys.path.append(os.path.dirname(__file__))

# Rendered when this tool got nothing: no join match, no call, no key. Every real Mend
# answer gets a real word instead, so a reader can tell "Mend says no" from "we failed".
NO_DATA = "-"

REACHABILITY_LABELS = {
    "REACHABLE": "Reachable",
    "POTENTIALLY_REACHABLE": "Potentially Reachable",
    "UNREACHABLE": "Unreachable",
    "REACHABILITY_UNAVAILABLE": "Reachability Unavailable",
}

MATURITY_LABELS = {
    "UNPROVEN": "Unproven",
    "POC_CODE": "PoC Code",
    "FUNCTIONAL": "Functional",
    "HIGH": "High",
    "NOT_DEFINED": "Not Defined",
}


def _get(obj, *path):
    """Walk a dot-path, returning None if any hop is missing or not a dict."""
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def extract_values(finding: dict) -> dict:
    """The four enrichment values off one 3.0 finding.

    Nothing in SecurityFindingDTOV3 is declared required, and the DTO carries a
    threatAssessment while also nesting a VulnerabilityProfileDTO that carries its own —
    so read both. Keys whose value is None are omitted rather than stored: the renderers
    treat an absent key as "we got nothing" and a present one as a real Mend answer.
    """
    values = {}
    candidates = {
        "reachability": _get(finding, "reachability"),
        "epss": _get(finding, "threatAssessment", "epssPercentage"),
        "maturity": _get(finding, "threatAssessment", "exploitCodeMaturity"),
        "exploitable": _get(finding, "exploitable"),
    }
    if candidates["epss"] is None:
        candidates["epss"] = _get(finding, "vulnerability", "threatAssessment", "epssPercentage")
    if candidates["maturity"] is None:
        candidates["maturity"] = _get(finding, "vulnerability", "threatAssessment", "exploitCodeMaturity")
    for key, value in candidates.items():
        if value is not None:
            values[key] = value
    return values


def build_index(findings: list) -> dict:
    """{(cve_name, library_uuid): values} for one project's 3.0 findings."""
    index = {}
    for finding in findings or []:
        cve = _get(finding, "name")
        lib_uuid = _get(finding, "component", "uuid")
        if not cve or not lib_uuid:
            continue
        index[(cve, lib_uuid)] = extract_values(finding)
    return index


def decorate_policy_violations(sorted_libs: list, index: dict):
    """Write 3.0 values onto the 1.4 issue objects, in place.

    The join is (CVE name, library UUID) and has no looser fallback: one CVE can affect
    several libraries in a project, so a CVE-only match would attribute reachability to the
    wrong library — confidently wrong is worse than blank in a triage field.

    Returns (candidates, matched, max_epss). The caller needs candidates to tell "nothing to
    match" from "matched nothing"; the second is the signal that the join key is wrong.
    """
    candidates = 0
    matched = 0
    max_epss = None
    for prj_el in sorted_libs or []:
        lib_uuid = _get(prj_el, "library", "keyUuid")
        violations = _get(prj_el, "policyViolations")
        for policy_el in violations or []:
            cve = _get(policy_el, "vulnerability", "name")
            if not cve or not lib_uuid:
                continue
            candidates += 1
            values = index.get((cve, lib_uuid))
            if values is None:
                continue
            matched += 1
            if "reachability" in values:
                policy_el["reachability"] = values["reachability"]
            if "exploitable" in values:
                policy_el["exploitable"] = values["exploitable"]
            threat = {}
            if "epss" in values:
                threat["epssPercentage"] = values["epss"]
                if isinstance(values["epss"], (int, float)) and \
                        (max_epss is None or values["epss"] > max_epss):
                    max_epss = values["epss"]
            if "maturity" in values:
                threat["exploitCodeMaturity"] = values["maturity"]
            # Only ever decorate a vulnerability Mend actually sent. A license policy
            # violation has none, and creating one would put vulnerability fields on a
            # Work Item that describes a license.
            if threat and isinstance(_get(policy_el, "vulnerability"), dict):
                policy_el["vulnerability"]["threatAssessment"] = threat
    return candidates, matched, max_epss


def format_reachability(policy_el: dict) -> str:
    value = _get(policy_el, "reachability")
    if value is None:
        return NO_DATA
    # dict.get() raises TypeError: unhashable type on a dict/list key. _get only guarantees
    # the CONTAINER is a dict, never the leaf type, so an unexpected object/array from Mend
    # must not propagate — this function is called unguarded from inside create_wi.
    if not isinstance(value, str):
        return NO_DATA
    return REACHABILITY_LABELS.get(value, str(value))


def format_epss(policy_el: dict) -> str:
    """Rendered as a 0-1 probability times 100 (decision, 2026-08-19).

    Presence is tested with `is None`, never truthiness: 0.0 is a valid EPSS score.
    """
    raw = _get(policy_el, "vulnerability", "threatAssessment", "epssPercentage")
    if raw is None:
        return NO_DATA
    try:
        return f"{float(raw) * 100:.1f}%"
    except (TypeError, ValueError):
        return NO_DATA


def format_exploit(policy_el: dict) -> str:
    maturity = _get(policy_el, "vulnerability", "threatAssessment", "exploitCodeMaturity")
    if maturity is not None:
        # See format_reachability: dict.get() raises on an unhashable (dict/list) key, and
        # this function is called unguarded from inside create_wi.
        if not isinstance(maturity, str):
            return NO_DATA
        return MATURITY_LABELS.get(maturity, str(maturity))
    exploitable = _get(policy_el, "exploitable")
    if exploitable is True:
        return "Yes"
    if exploitable is False:
        return "No"
    return NO_DATA
