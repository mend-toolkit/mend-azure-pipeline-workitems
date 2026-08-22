import pytest

from mend_azure_wi_sync import source3


@pytest.mark.parametrize("raw,expected", [
    ("low", 0.1), ("LOW", 0.1), ("  low  ", 0.1),
    ("medium", 4.0), ("high", 7.0), ("critical", 9.0),
    ("7.0", 7.0), ("7", 7.0), ("0", 0.0), ("10", 10.0),
])
def test_bands_and_numbers_resolve_to_a_floor(raw, expected):
    assert source3.severity_floor(raw) == expected


def test_an_unset_threshold_defaults_to_high():
    """An operator who enables the feature without choosing gets the conventional default,
    not everything."""
    assert source3.severity_floor("") == 7.0
    assert source3.severity_floor(None) == 7.0


def test_nonsense_falls_back_to_high_rather_than_letting_everything_through():
    assert source3.severity_floor("banana") == 7.0
    assert source3.severity_floor("-3") == 7.0
    assert source3.severity_floor("99") == 7.0


def test_a_score_at_the_floor_is_included():
    """'high' must mean >= 7.0, not > 7.0, or every exactly-7.0 CVE silently vanishes."""
    assert source3.meets_threshold(7.0, 7.0) is True


def test_a_score_below_the_floor_is_excluded():
    assert source3.meets_threshold(6.9, 7.0) is False


def test_an_unscored_finding_is_included():
    """Spec 5.1: a finding vanishing because Mend has not scored it yet is the worse failure."""
    assert source3.meets_threshold(None, 7.0) is True
    assert source3.meets_threshold("", 7.0) is True


def test_a_nonnumeric_score_is_included_rather_than_dropped():
    assert source3.meets_threshold("not-a-number", 7.0) is True


def test_zero_is_a_real_score_not_a_missing_one():
    """0.0 is a valid CVSS score and must be COMPARED, not treated as unscored."""
    assert source3.meets_threshold(0.0, 7.0) is False


def _finding(cve="CVE-1", lib="log4j-core", status="ACTIVE", score=9.8,
             finding_status="UNREVIEWED"):
    return {
        "uuid": f"u-{cve}",
        "name": cve,
        "type": "SECURITY_VULNERABILITY",
        "findingInfo": {"status": status, "findingStatus": finding_status},
        "component": {"name": lib, "version": "2.14.1", "uuid": f"c-{lib}"},
        "vulnerability": {"name": cve, "score": score, "severity": "HIGH"},
    }


def test_an_active_finding_above_the_threshold_is_kept():
    entries, unscored = source3.normalise_findings([_finding()], 7.0)
    assert list(entries) == ["log4j-core"]
    assert entries["log4j-core"]["kind"] == "vulnerability"
    assert len(entries["log4j-core"]["findings"]) == 1
    assert unscored == 0


def test_findings_for_one_library_are_grouped_into_one_entry():
    entries, _ = source3.normalise_findings(
        [_finding(cve="CVE-1"), _finding(cve="CVE-2")], 7.0)
    assert list(entries) == ["log4j-core"]
    assert len(entries["log4j-core"]["findings"]) == 2


def test_different_libraries_get_separate_entries():
    entries, _ = source3.normalise_findings(
        [_finding(lib="log4j-core"), _finding(lib="jackson-databind")], 7.0)
    assert sorted(entries) == ["jackson-databind", "log4j-core"]


@pytest.mark.parametrize("status", ["IGNORED", "LIBRARY_REMOVED",
                                    "LIBRARY_IN_HOUSE", "LIBRARY_WHITELIST"])
def test_every_non_active_status_is_excluded(status):
    """This is what lets Plan 4 close the work item. IGNORED is a Mend suppression;
    LIBRARY_REMOVED is the library being gone."""
    entries, _ = source3.normalise_findings([_finding(status=status)], 7.0)
    assert entries == {}


def test_a_suppressed_finding_leaves_no_entry_even_alongside_an_active_one():
    entries, _ = source3.normalise_findings(
        [_finding(cve="CVE-1", status="IGNORED"), _finding(cve="CVE-2", status="ACTIVE")], 7.0)
    assert len(entries["log4j-core"]["findings"]) == 1
    assert entries["log4j-core"]["findings"][0]["name"] == "CVE-2"


def test_the_library_disappears_when_all_its_findings_are_suppressed():
    """The closure case: an entry that would be empty must not exist at all, or Plan 4 will
    keep the work item open forever."""
    entries, _ = source3.normalise_findings(
        [_finding(cve="CVE-1", status="IGNORED"), _finding(cve="CVE-2", status="IGNORED")], 7.0)
    assert entries == {}


@pytest.mark.parametrize("finding_status", ["SUPPRESSED", "REMEDIATED", "IN_REVIEW",
                                            "ISSUE_CREATED"])
def test_finding_status_is_deliberately_ignored(finding_status):
    """An analyst workflow field must not drive work item state, or items oscillate."""
    entries, _ = source3.normalise_findings(
        [_finding(status="ACTIVE", finding_status=finding_status)], 7.0)
    assert list(entries) == ["log4j-core"]


def test_a_finding_below_the_threshold_is_excluded():
    entries, _ = source3.normalise_findings([_finding(score=4.0)], 7.0)
    assert entries == {}


def test_an_unscored_finding_is_kept_and_counted():
    entries, unscored = source3.normalise_findings([_finding(score=None)], 7.0)
    assert list(entries) == ["log4j-core"]
    assert unscored == 1


def test_a_finding_with_no_library_name_is_skipped_not_crashed():
    broken = _finding()
    del broken["component"]
    entries, _ = source3.normalise_findings([broken, _finding()], 7.0)
    assert list(entries) == ["log4j-core"]


def test_garbage_input_returns_empty_rather_than_raising():
    assert source3.normalise_findings(None, 7.0) == ({}, 0)
    assert source3.normalise_findings(["not a dict"], 7.0) == ({}, 0)


def _violation(lib="log4j-core", finding_type="LEGAL", name="GPL-3.0"):
    return {"uuid": f"v-{lib}", "name": name, "findingType": finding_type,
            "originName": lib, "originUuid": f"o-{lib}", "risk": "HIGH",
            "violationType": "LICENSE"}


def test_a_legal_violation_becomes_a_license_entry():
    entries = source3.normalise_violations([_violation()])
    assert list(entries) == ["log4j-core"]
    assert entries["log4j-core"]["kind"] == "license"


@pytest.mark.parametrize("finding_type", ["SECURITY", "LIBRARY"])
def test_non_legal_finding_types_are_ignored(finding_type):
    """SECURITY violations would duplicate the findings path; LIBRARY has no meaning here."""
    assert source3.normalise_violations([_violation(finding_type=finding_type)]) == {}


def test_several_violations_for_one_library_group_together():
    entries = source3.normalise_violations(
        [_violation(name="GPL-3.0"), _violation(name="AGPL-3.0")])
    assert len(entries["log4j-core"]["findings"]) == 2


def test_a_violation_with_no_origin_name_is_skipped():
    broken = _violation()
    del broken["originName"]
    assert source3.normalise_violations([broken]) == {}


def test_garbage_violations_return_empty_rather_than_raising():
    assert source3.normalise_violations(None) == {}
    assert source3.normalise_violations(["nope"]) == {}


# --- per-CVE grouping (MEND_DEPENDENCY=false) --------------------------------------------------

def _sec(cve="CVE-2021-44228", lib="log4j-core", score=9.8, status="ACTIVE"):
    return {"component": {"name": lib},
            "vulnerability": {"name": cve, "score": score},
            "findingInfo": {"status": status}}


def test_per_cve_keys_by_cve_and_library():
    """The key must be the WORK ITEM's identity, which in this mode is one CVE in one library --
    otherwise reconciliation cannot find the item the title decodes to."""
    entries, _ = source3.normalise_findings(
        [_sec(), _sec(cve="CVE-2021-45046")], 7.0, per_cve=True)
    assert sorted(entries) == ["CVE-2021-44228|log4j-core", "CVE-2021-45046|log4j-core"]
    assert entries["CVE-2021-44228|log4j-core"]["library"] == "log4j-core"
    assert len(entries["CVE-2021-44228|log4j-core"]["findings"]) == 1


def test_one_cve_in_two_libraries_is_two_entries():
    """Keying on the CVE alone collides here -- common, and it would close a live work item."""
    entries, _ = source3.normalise_findings(
        [_sec(), _sec(lib="log4j-api")], 7.0, per_cve=True)
    assert sorted(entries) == ["CVE-2021-44228|log4j-api", "CVE-2021-44228|log4j-core"]


def test_dependency_mode_grouping_is_untouched():
    """The default mode keeps one entry per library holding every CVE."""
    entries, _ = source3.normalise_findings([_sec(), _sec(cve="CVE-2021-45046")], 7.0)
    assert list(entries) == ["log4j-core"]
    assert len(entries["log4j-core"]["findings"]) == 2


def test_the_default_is_dependency_mode():
    entries_default, _ = source3.normalise_findings([_sec()], 7.0)
    entries_explicit, _ = source3.normalise_findings([_sec()], 7.0, per_cve=False)
    assert list(entries_default) == list(entries_explicit) == ["log4j-core"]


def test_a_suppressed_cve_leaves_no_entry_which_is_what_closes_its_work_item():
    entries, _ = source3.normalise_findings(
        [_sec(status="IGNORED"), _sec(cve="CVE-2021-45046")], 7.0, per_cve=True)
    assert list(entries) == ["CVE-2021-45046|log4j-core"]


def test_a_finding_with_no_cve_name_is_dropped_in_per_cve_mode():
    """It has no title to render, so an entry for it could never be satisfied -- reconciliation
    would report a create every run and nothing would ever appear."""
    nameless = _sec()
    nameless["vulnerability"].pop("name")
    entries, _ = source3.normalise_findings([nameless, _sec()], 7.0, per_cve=True)
    assert list(entries) == ["CVE-2021-44228|log4j-core"]
    # In dependency mode it still counts towards its library.
    entries, _ = source3.normalise_findings([nameless], 7.0)
    assert list(entries) == ["log4j-core"]
