"""Vulnerability work items group by ROOT library, not by vulnerable library.

An operator cannot upgrade a transitive library. `qs-6.5.2.tgz` is pulled in by `express` and
`body-parser`, and those are what a person can change -- so the work item names the root and lists
what it drags in. Mend's own repo integrations group this way.

Verified live (project 204e5967, 2026-08-23): multi-root is common, not exotic --
`cookie-0.3.1.tgz` has three roots, and `body-parser-1.18.3.tgz` is BOTH a direct dependency and
transitive via `express`, carrying two dependencyContexts.
"""

from mend_azure_wi_sync import source3


def _finding(cve="CVE-2022-24999", lib="qs-6.5.2.tgz", score=7.5, roots=(("express-4.16.4.tgz", "4.16.4"),),
             status="ACTIVE", contexts=None):
    """One SecurityFindingDTOV3, shaped like the live response."""
    if contexts is None:
        contexts = [{
            "dependencyType": "TRANSITIVE", "isDirect": False, "isTransitive": True,
            "directRoots": [{"rootLibraryUuid": f"uuid-{n}", "rootLibraryName": n,
                             "rootLibraryVersion": v} for n, v in roots],
        }]
    return {
        "findingInfo": {"status": status},
        "component": {"name": lib, "version": "6.5.2"},
        "vulnerability": {"name": cve, "score": score, "severity": "HIGH"},
        "dependencyContexts": contexts,
    }


# ------------------------------------------------------------------------------- root_names()

def test_a_single_root_is_returned():
    assert source3.root_names(_finding()) == ["express-4.16.4.tgz"]


def test_every_root_is_returned_sorted():
    """Sorted, not API order: an unstable list reshuffles descriptions and rewrites every work
    item in the project for no reason (see 5c53f8a)."""
    finding = _finding(roots=(("express-4.16.4.tgz", "4.16.4"), ("body-parser-1.18.3.tgz", "1.18.3")))
    assert source3.root_names(finding) == ["body-parser-1.18.3.tgz", "express-4.16.4.tgz"]


def test_roots_across_several_contexts_are_all_returned():
    """body-parser is both DIRECT (root = itself) and TRANSITIVE via express -- two contexts."""
    finding = _finding(lib="body-parser-1.18.3.tgz", contexts=[
        {"dependencyType": "DIRECT", "isDirect": True, "directRoots": [
            {"rootLibraryName": "body-parser-1.18.3.tgz", "rootLibraryVersion": "1.18.3"}]},
        {"dependencyType": "TRANSITIVE", "isDirect": False, "directRoots": [
            {"rootLibraryName": "express-4.16.4.tgz", "rootLibraryVersion": "4.16.4"}]},
    ])
    assert source3.root_names(finding) == ["body-parser-1.18.3.tgz", "express-4.16.4.tgz"]


def test_a_duplicate_root_is_returned_once():
    finding = _finding(roots=(("express-4.16.4.tgz", "4.16.4"), ("express-4.16.4.tgz", "4.16.4")))
    assert source3.root_names(finding) == ["express-4.16.4.tgz"]


def test_a_finding_with_no_contexts_falls_back_to_its_own_library():
    """Never drop a finding for a missing context: a work item that should exist and does not is
    strictly worse than one filed under the library itself."""
    finding = _finding()
    finding.pop("dependencyContexts")
    assert source3.root_names(finding) == ["qs-6.5.2.tgz"]


def test_malformed_contexts_fall_back_rather_than_raising():
    for broken in ("nope", [], [{}], [{"directRoots": None}], [{"directRoots": [{}]}]):
        finding = _finding()
        finding["dependencyContexts"] = broken
        assert source3.root_names(finding) == ["qs-6.5.2.tgz"], broken


def test_a_finding_with_no_component_name_and_no_roots_yields_nothing():
    finding = {"findingInfo": {"status": "ACTIVE"}, "vulnerability": {"name": "CVE-1", "score": 9}}
    assert source3.root_names(finding) == []


# -------------------------------------------------------------------- normalise_findings(), roots

def test_entries_are_keyed_by_root_and_carry_the_root_as_library():
    entries, _ = source3.normalise_findings([_finding()], 7.0)
    assert list(entries) == ["express-4.16.4.tgz"]
    assert entries["express-4.16.4.tgz"]["library"] == "express-4.16.4.tgz"
    assert entries["express-4.16.4.tgz"]["kind"] == "vulnerability"


def test_one_finding_with_two_roots_lands_in_both_entries():
    finding = _finding(roots=(("express-4.16.4.tgz", "4.16.4"), ("body-parser-1.18.3.tgz", "1.18.3")))
    entries, _ = source3.normalise_findings([finding], 7.0)
    assert sorted(entries) == ["body-parser-1.18.3.tgz", "express-4.16.4.tgz"]
    for entry in entries.values():
        assert entry["findings"] == [finding]


def test_several_libraries_under_one_root_share_an_entry():
    qs = _finding(cve="CVE-2022-24999", lib="qs-6.5.2.tgz")
    cookie = _finding(cve="CVE-2024-47764", lib="cookie-0.3.1.tgz", score=9.0)
    entries, _ = source3.normalise_findings([qs, cookie], 7.0)
    assert list(entries) == ["express-4.16.4.tgz"]
    assert len(entries["express-4.16.4.tgz"]["findings"]) == 2


def test_a_suppressed_finding_is_excluded_before_grouping():
    """IGNORED means the work item should close, so the root must not be held open by it."""
    entries, _ = source3.normalise_findings([_finding(status="IGNORED")], 7.0)
    assert entries == {}


def test_a_finding_below_the_threshold_is_excluded_before_grouping():
    entries, _ = source3.normalise_findings([_finding(score=4.0)], 7.0)
    assert entries == {}


def test_a_root_whose_only_finding_is_filtered_produces_no_entry():
    """That absence is what tells reconciliation to close the work item."""
    entries, _ = source3.normalise_findings(
        [_finding(status="IGNORED"), _finding(cve="CVE-2", lib="cookie-0.3.1.tgz",
                                             roots=(("helmet-2.3.0.tgz", "2.3.0"),))], 7.0)
    assert list(entries) == ["helmet-2.3.0.tgz"]


def test_unscored_findings_are_still_counted_once_not_once_per_root():
    """The unscored tally is a project-level report, not a per-entry one."""
    finding = _finding(score=None, roots=(("express-4.16.4.tgz", "4.16.4"),
                                          ("body-parser-1.18.3.tgz", "1.18.3")))
    entries, unscored = source3.normalise_findings([finding], 7.0)
    assert len(entries) == 2
    assert unscored == 1


def test_per_cve_mode_is_untouched_and_still_keys_on_the_vulnerable_library():
    entries, _ = source3.normalise_findings([_finding()], 7.0, per_cve=True)
    assert list(entries) == ["CVE-2022-24999|qs-6.5.2.tgz"]
    assert entries["CVE-2022-24999|qs-6.5.2.tgz"]["library"] == "qs-6.5.2.tgz"


def test_garbage_input_never_raises():
    assert source3.normalise_findings(None, 7.0) == ({}, 0)
    assert source3.normalise_findings(["nope", 42, None], 7.0) == ({}, 0)
