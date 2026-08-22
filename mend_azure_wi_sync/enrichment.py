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


def format_reachability(policy_el: dict) -> str:
    value = _get(policy_el, "reachability")
    if value is None:
        return NO_DATA
    # dict.get() raises TypeError: unhashable type on a dict/list key. _get only guarantees
    # the CONTAINER is a dict, never the leaf type, so an unexpected object/array from Mend
    # must not propagate — this function is called unguarded from the render path.
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
        # unguarded from the render path.
        return NO_DATA


def format_exploit(policy_el: dict) -> str:
    maturity = _get(policy_el, "vulnerability", "threatAssessment", "exploitCodeMaturity")
    if maturity is None:
        return NO_DATA
    # See format_reachability: dict.get() raises on an unhashable (dict/list) key, and this
    # function is called unguarded from the render path.
    if not isinstance(maturity, str):
        return NO_DATA
    return MATURITY_LABELS.get(maturity, str(maturity))
