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


def test_an_unparseable_version_without_major_falls_back_to_unqualified():
    """recommendedFix equals version, no major present. major="" bypasses the series check."""
    for version in ("", "latest", "v", "-"):
        result = source3.root_remediation(_entry(version=version, recommended=version, major=""))
        assert result["fix"] == "none available", version
        assert result["major"] == ""


def test_an_unparseable_version_with_major_rejects_the_guessed_series():
    """recommendedFix equals version, major present. The series.isdigit() check MUST reject
    unparseable leading components and not print them. version="latest" must never produce
    "none available in latest.x" -- that would be false and misleading."""
    for version in ("", "latest", "v", "-"):
        result = source3.root_remediation(_entry(version=version, recommended=version,
                                                  major="4.0.3"))
        # The series-check must have rejected it and fallen back to the unqualified form
        assert result["fix"] == "none available", f"version={version}: {result['fix']}"
        # major must survive: the installed version is unparseable, but the major fix exists
        assert result["major"] == "4.0.3", version


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


# ------------------------------------------------------------------------ rendering the block

from unittest import mock

from mend_azure_wi_sync import core


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false", reponame="",
                  routing="false", description="ReproSteps", priority="false", azure_area="",
                  azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _finding(cve="CVE-2022-24999", lib="qs-6.5.2.tgz", score=7.5, root="express-4.16.4.tgz"):
    return {
        "findingInfo": {"status": "ACTIVE"},
        "component": {"name": lib, "version": "6.5.2", "dependencyType": "Transitive",
                      "dependencyFile": "/s/package.json", "references": {}},
        "vulnerability": {"name": cve, "score": score, "severity": "HIGH",
                          "description": "A querystring DoS.",
                          "references": [{"url": f"https://nvd.nist.gov/{cve}", "advisory": True}]},
        "topFix": {"fixResolution": "qs - 6.5.3", "type": "UPGRADE_VERSION"},
        "dependencyContexts": [{"isTransitive": True, "directRoots": [
            {"rootLibraryName": root, "rootLibraryVersion": "4.16.4"}]}],
    }


def _root_entry(**overrides):
    values = dict(version="4.16.4", recommended_fix="4.22.2", major_fix="5.2.1",
                  fix_failed=False, severity="HIGH", total=13)
    values.update(overrides)
    return values


def _render(findings, root_entry):
    entry = {"library": "express-4.16.4.tgz", "kind": "vulnerability", "findings": findings,
             "licenses": [], "component": {}, "root": root_entry}
    with mock.patch.object(core, "conf", _conf()):
        return core.render_entry_v3("vulnerability", "express-4.16.4.tgz", entry, False)[0]


def test_the_block_states_both_labels_with_the_agreed_wording():
    html = core.remediation_block_v3({"fix": "4.22.2", "major": "5.2.1", "note": ""})
    assert "Recommended Fix" in html
    assert "4.22.2" in html
    assert "Recommended Major Version" in html
    assert "5.2.1" in html


def test_the_block_uses_only_markup_azure_is_known_to_keep():
    """Azure DevOps rewrites and DELETES markup it dislikes -- this branch was bitten twice. The
    inline-styled table is the pattern already proven to survive (create_html_table)."""
    html = core.remediation_block_v3({"fix": "4.22.2", "major": "5.2.1", "note": ""})
    assert "<table" in html
    for banned in ("<div", "<span", "<h1", "<h2", "<h3", "<section"):
        assert banned not in html


def test_an_absent_major_version_omits_that_line_entirely():
    html = core.remediation_block_v3({"fix": "1.19.0", "major": "", "note": ""})
    assert "Recommended Fix" in html
    assert "Recommended Major Version" not in html


def test_an_all_empty_remediation_renders_nothing_at_all():
    assert core.remediation_block_v3({"fix": "", "major": "", "note": ""}) == ""
    assert core.remediation_block_v3({}) == ""


def test_the_note_is_rendered_when_present():
    html = core.remediation_block_v3({"fix": "none available", "major": "",
                                      "note": "Mend could not compute a fix for this library."})
    assert "could not compute" in html


def test_remediation_values_are_escaped():
    html = core.remediation_block_v3({"fix": "<script>x</script>", "major": "", "note": ""})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_the_block_appears_before_the_cve_table_in_the_description():
    desc = _render([_finding()], _root_entry())["desc"]
    assert desc.index("Recommended Fix") < desc.index("<table")  \
        if desc.count("<table") == 1 else True
    # The remediation block is itself a table, so compare against the CVE header instead.
    assert desc.index("Recommended Fix") < desc.index(">CVE<")


def test_the_header_says_root_library():
    desc = _render([_finding()], _root_entry())["desc"]
    assert "Root Library - </b>express-4.16.4.tgz" in desc


def test_the_dependency_column_names_the_real_vulnerable_library_per_row():
    """It was the same value on every row when items were per-library; under root grouping it is
    the one genuinely useful column in the table."""
    desc = _render([_finding(lib="qs-6.5.2.tgz"),
                    _finding(cve="CVE-2024-47764", lib="cookie-0.3.1.tgz")], _root_entry())["desc"]
    assert "qs-6.5.2.tgz" in desc
    assert "cookie-0.3.1.tgz" in desc


def test_the_fixed_in_column_is_gone():
    """Mend publishes no per-CVE root fix version, and a transitive version nobody can set was
    misleading. See the spec's "API limitation"."""
    desc = _render([_finding()], _root_entry())["desc"]
    assert "Fixed in" not in desc


def test_the_title_counts_surviving_findings_and_keeps_its_shape():
    item = _render([_finding(), _finding(cve="CVE-2024-47764", lib="cookie-0.3.1.tgz")],
                   _root_entry())
    assert item["title"] == "express-4.16.4.tgz: 2 vulnerabilities (highest severity is 7.5)"


def test_the_title_round_trips_through_the_closure_decoder():
    """The creation/closure contract. A title closure cannot decode strands a work item open
    forever or closes somebody else's."""
    from mend_azure_wi_sync import identity
    item = _render([_finding()], _root_entry())
    assert identity.parse_dependency_title(item["title"]) == "express-4.16.4.tgz"
    assert identity.matches_library(item["title"], "express-4.16.4.tgz") is True


def test_a_root_with_no_index_entry_renders_no_remediation_lines():
    desc = _render([_finding()], {})["desc"]
    assert "Recommended Fix" not in desc
    assert ">CVE<" in desc


def test_the_description_is_deterministic_across_reshuffled_findings():
    a = _finding(cve="CVE-A", lib="qs-6.5.2.tgz")
    b = _finding(cve="CVE-B", lib="cookie-0.3.1.tgz")
    assert _render([a, b], _root_entry())["desc"] == _render([b, a], _root_entry())["desc"]
