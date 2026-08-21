import os
import sys

sys.path.append(os.path.dirname(__file__))

# Rendered when this tool got nothing: no join match, no call, no key. Every real Mend
# answer gets a real word instead, so a reader can tell "Mend says no" from "we failed".
NO_DATA = "-"

# Mend's reachability vocabulary is two values. POTENTIALLY_REACHABLE and
# REACHABILITY_UNAVAILABLE were 3.0 spellings and are gone (confirmed 2026-08-21); the
# "not analyzed" case is carried by an ABSENT reachability key, which renders NO_DATA.
REACHABILITY_LABELS = {
    "REACHABLE": "Reachable",
    "UNREACHABLE": "Unreachable",
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


def _reachability_from_info(info):
    """`reachabilityInfo` -> "REACHABLE" / "UNREACHABLE" / None.

    None means "Mend did not tell us", which the renderer shows as NO_DATA. analyzed=false
    occurs only when reachability analysis has not run for the project (confirmed live
    2026-08-21), so it is exactly that case rather than a third reachability state.

    `reachable` is tested with `is True` / `is False`, never truthiness: a string or null
    from an unexpected payload must read as "not told", not as a confident answer. In a
    triage field, confidently wrong is worse than blank.
    """
    if not isinstance(info, dict):
        return None
    if info.get("analyzed") is not True:
        return None
    reachable = info.get("reachable")
    if reachable is True:
        return "REACHABLE"
    if reachable is False:
        return "UNREACHABLE"
    return None


def extract_alert_values(alert: dict) -> dict:
    """The three enrichment values off one 1.4 alert.

    Field paths verified live 2026-08-21 against getProjectAlertsByType. Unlike the 3.0
    finding this replaces, an alert nests threatAssessment only under `vulnerability`, so
    there is no second location to read, and it carries no `exploitable` field at all --
    exploitCodeMaturity is the exploitability signal, matching Mend's repo integration.

    Keys whose value is unavailable are omitted rather than stored as None: the renderers
    treat an absent key as "we got nothing" and a present one as a real Mend answer.
    """
    values = {}
    candidates = {
        "reachability": _reachability_from_info(_get(alert, "reachabilityInfo")),
        "epss": _get(alert, "vulnerability", "threatAssessment", "epssPercentage"),
        "maturity": _get(alert, "vulnerability", "threatAssessment", "exploitCodeMaturity"),
    }
    for key, value in candidates.items():
        if value is not None:
            values[key] = value
    return values


def build_alert_index(alerts: list) -> dict:
    """{(cve_name, library_key_uuid): values} for one project's 1.4 alerts.

    Both halves of the key are 1.4 field names in the same identifier space as
    fetchProjectPolicyIssues, so this join has no cross-generation assumption to get wrong --
    which is the whole reason enrichment moved off 3.0.

    An alert with no extractable values is omitted, so decorate_policy_violations' `matched`
    count stays honest: a match that carries nothing is not a match.
    """
    index = {}
    for alert in alerts or []:
        cve = _get(alert, "vulnerability", "name")
        lib_uuid = _get(alert, "library", "keyUuid")
        if not cve or not lib_uuid:
            continue
        values = extract_alert_values(alert)
        if values:
            index[(cve, lib_uuid)] = values
    return index


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

    Returns (candidates, matched). The caller needs candidates to tell "nothing to match"
    from "matched nothing"; the second is the signal that the join key is wrong.
    """
    candidates = 0
    matched = 0
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
            threat = {}
            if "epss" in values:
                threat["epssPercentage"] = values["epss"]
            if "maturity" in values:
                threat["exploitCodeMaturity"] = values["maturity"]
            # Only ever decorate a vulnerability Mend actually sent. A license policy
            # violation has none, and creating one would put vulnerability fields on a
            # Work Item that describes a license.
            if threat and isinstance(_get(policy_el, "vulnerability"), dict):
                # Merge onto whatever 1.4 already sent under this key rather than replacing
                # it outright — a MEND_CUSTOMFIELDS dot-path reading another sub-key here
                # must not silently start seeing "No content" once enrichment is on. Only
                # merge into an existing dict; anything else (absent, or an unexpected
                # non-dict value from 1.4) is set outright, since there is nothing sane to
                # merge onto.
                existing = policy_el["vulnerability"].get("threatAssessment")
                if isinstance(existing, dict):
                    existing.update(threat)
                else:
                    policy_el["vulnerability"]["threatAssessment"] = threat
    return candidates, matched


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


# Anything below one percent renders as this rather than a rounded number, matching Mend's own
# repo integration so one score does not read differently on two Mend surfaces. It also avoids a
# precision trap: most CVEs score well under 1%, so one decimal on a 0-100 scale would compress
# the bulk of the real distribution into "0.0%" and "0.1%". Verified live 2026-08-21 --
# epssPercentage 0.253 is 0.25% in the Mend UI, which one decimal renders as a misleading "0.3%".
EPSS_BELOW_ONE = "<1%"


def format_epss(policy_el: dict) -> str:
    """epssPercentage is already a percentage, on a 0-100 scale.

    Confirmed against live Mend data 2026-08-19 and again 2026-08-21 (raw 0.253 reads 0.25% in
    the UI). It was briefly read as a 0-1 probability and multiplied by 100, which rendered every
    score 100x too high — a real 0.8% showed as 80.0%. In a triage column that is the difference
    between "ignore" and "drop everything", and nothing in the value itself reveals the error.

    Presence is tested with `is None`, never truthiness: 0.0 is a valid EPSS score, and it
    renders as EPSS_BELOW_ONE — a real answer — not as NO_DATA.
    """
    raw = _get(policy_el, "vulnerability", "threatAssessment", "epssPercentage")
    if raw is None:
        return NO_DATA
    try:
        value = float(raw)
        if value < 1:
            return EPSS_BELOW_ONE
        return f"{value:.1f}%"
    except (TypeError, ValueError, OverflowError):
        # OverflowError: float() of a very large JSON integer (e.g. from a malformed
        # payload) overflows rather than raising ValueError, and this formatter is called
        # unguarded from inside create_wi.
        return NO_DATA


def format_exploit(policy_el: dict) -> str:
    maturity = _get(policy_el, "vulnerability", "threatAssessment", "exploitCodeMaturity")
    if maturity is None:
        return NO_DATA
    # See format_reachability: dict.get() raises on an unhashable (dict/list) key, and this
    # function is called unguarded from inside create_wi.
    if not isinstance(maturity, str):
        return NO_DATA
    return MATURITY_LABELS.get(maturity, str(maturity))
