import os
import sys

sys.path.append(os.path.dirname(__file__))

# Rendered whenever Mend supplies no value for a field, so a missing answer is distinguishable
# from a real one.
NO_DATA = "-"

# Mend's reachability vocabulary. An absent reachability key renders NO_DATA.
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
    """A finding's reachability as a display label, or NO_DATA when absent or not a string."""
    value = _get(policy_el, "reachability")
    if value is None:
        return NO_DATA
    # A non-string value renders NO_DATA: dict.get() raises TypeError on a dict or list key, and
    # this is called unguarded from the render path.
    if not isinstance(value, str):
        return NO_DATA
    return REACHABILITY_LABELS.get(value, str(value))


# Any score below one percent renders as this rather than a rounded number.
EPSS_BELOW_ONE = "<1%"


def format_epss(policy_el: dict) -> str:
    """A finding's EPSS score as a display string, or NO_DATA when absent or unparseable.

    `epssPercentage` is already a percentage, on a 0-100 scale. Presence is tested with `is None`,
    never truthiness: 0.0 is a valid score and renders as EPSS_BELOW_ONE, not as NO_DATA.
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
        # OverflowError: float() of a very large JSON integer overflows rather than raising
        # ValueError, and this formatter is called unguarded from the render path.
        return NO_DATA


def format_exploit(policy_el: dict) -> str:
    """A finding's exploit code maturity as a display label, or NO_DATA when absent or not a
    string."""
    maturity = _get(policy_el, "vulnerability", "threatAssessment", "exploitCodeMaturity")
    if maturity is None:
        return NO_DATA
    # See format_reachability: dict.get() raises on an unhashable (dict/list) key, and this
    # function is called unguarded from the render path.
    if not isinstance(maturity, str):
        return NO_DATA
    return MATURITY_LABELS.get(maturity, str(maturity))
