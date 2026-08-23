"""What "Recommended Fix" and "Recommended Major Version" say.

recommendedFix is a bare version, but live it FREQUENTLY EQUALS the installed version, which means
"no fix inside the current major". Verified 2026-08-23 -- forever 2.0.0 -> 2.0.0, mongodb 2.2.36 ->
2.2.36, helmet 2.3.0 -> 2.3.0, swig 1.4.2 -> 1.4.2, underscore 1.9.1 -> 1.9.1, csurf 1.9.0 ->
1.9.0, against express 4.16.4 -> 4.22.2 and marked 0.3.5 -> 0.8.2. Six of ten roots in that project
had no in-major fix, so this is the common case and telling somebody on 2.0.0 to "upgrade to 2.0.0"
would be the common output of a naive renderer.

Mend does NOT publish which CVEs a given root version fixes -- see the spec's "API limitation".
So these values are stated as Mend's verdict for the library and never as per-CVE coverage.
"""

from mend_azure_wi_sync import source3


def _entry(version="4.16.4", recommended="4.22.2", major="5.2.1", failed=False):
    return {"version": version, "recommended_fix": recommended, "major_fix": major,
            "fix_failed": failed, "severity": "HIGH", "total": 13}


def test_a_real_in_major_fix_is_stated_plainly():
    assert source3.root_remediation(_entry()) == {
        "fix": "4.22.2", "major": "5.2.1", "note": ""}


def test_an_in_major_fix_with_no_major_upgrade_states_only_the_fix():
    """express-session live: recommendedFix 1.19.0, no fixForMajorVersion."""
    result = source3.root_remediation(_entry(version="1.15.6", recommended="1.19.0", major=""))
    assert result["fix"] == "1.19.0"
    assert result["major"] == ""


def test_a_recommended_fix_equal_to_the_installed_version_says_none_available_in_that_major():
    """forever live: 2.0.0 -> 2.0.0 with a 4.0.3 major. "Upgrade to 2.0.0" from 2.0.0 is worse
    than saying nothing."""
    result = source3.root_remediation(_entry(version="2.0.0", recommended="2.0.0", major="4.0.3"))
    assert result["fix"] == "none available in 2.x"
    assert result["major"] == "4.0.3"


def test_no_in_major_fix_and_no_major_fix_says_none_available():
    """swig live: 1.4.2 -> 1.4.2, no major. Genuinely nothing to do."""
    result = source3.root_remediation(_entry(version="1.4.2", recommended="1.4.2", major=""))
    assert result["fix"] == "none available"
    assert result["major"] == ""


def test_the_major_series_comes_from_the_installed_versions_leading_component():
    result = source3.root_remediation(_entry(version="2.2.36", recommended="2.2.36", major="7.3.0"))
    assert result["fix"] == "none available in 2.x"


def test_an_unparseable_version_falls_back_to_the_unqualified_wording():
    """Never print a guessed series."""
    for version in ("", "latest", "v", "-"):
        result = source3.root_remediation(_entry(version=version, recommended=version, major=""))
        assert result["fix"] == "none available", version


def test_a_failed_fix_computation_is_reported_as_such():
    """Different from "no fix exists": Mend tried and could not."""
    result = source3.root_remediation(_entry(version="1.4.2", recommended="1.4.2", major="",
                                             failed=True))
    assert result["note"] == "Mend could not compute a fix for this library."


def test_a_missing_recommended_fix_is_not_reported_as_a_fix():
    result = source3.root_remediation(_entry(recommended=""))
    assert result["fix"] == "none available"
    assert result["major"] == "5.2.1"


def test_an_absent_or_malformed_entry_yields_all_empty_so_nothing_renders():
    """A root missing from the index (a partial read) must render no remediation lines at all --
    NOT "none available", which would assert something we did not read."""
    for missing in ({}, None, "nope", []):
        assert source3.root_remediation(missing) == {"fix": "", "major": "", "note": ""}
