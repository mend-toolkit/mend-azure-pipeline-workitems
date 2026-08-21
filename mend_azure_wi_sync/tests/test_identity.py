from mend_azure_wi_sync import identity


def test_vulnerability_title_is_the_library_name_alone():
    assert identity.vulnerability_title("log4j-core") == "log4j-core"


def test_vulnerability_title_is_stable_across_suppression():
    """The whole point: the title must not encode a count or a score."""
    before = identity.vulnerability_title("log4j-core")
    after = identity.vulnerability_title("log4j-core")
    assert before == after == "log4j-core"


def test_vulnerability_title_strips_surrounding_whitespace():
    assert identity.vulnerability_title("  log4j-core  ") == "log4j-core"


def test_cve_title_carries_no_severity():
    assert identity.cve_title("CVE-2021-44228", "log4j-core") == \
        "CVE-2021-44228 detected in log4j-core"


def test_license_title_is_unchanged_from_the_shipped_format():
    assert identity.license_title("log4j-core") == \
        "License Policy Violation detected in log4j-core"


def test_titles_tolerate_empty_inputs_without_raising():
    assert identity.vulnerability_title("") == ""
    assert identity.cve_title("", "") == " detected in "
    assert identity.license_title("") == "License Policy Violation detected in "


def test_recognises_the_shipped_dependency_title():
    assert identity.is_legacy_vulnerability_title(
        "log4j-core: 3 vulnerabilities (highest severity is 9.8)", "log4j-core") is True


def test_recognises_it_with_any_count_and_score():
    assert identity.is_legacy_vulnerability_title(
        "log4j-core: 1 vulnerabilities (highest severity is )", "log4j-core") is True


def test_does_not_match_a_different_library():
    """'log4j' must not claim 'log4j-core''s work item."""
    assert identity.is_legacy_vulnerability_title(
        "log4j-core: 3 vulnerabilities (highest severity is 9.8)", "log4j") is False


def test_does_not_match_the_new_title():
    """The new title is handled by exact match; the fallback must not double-claim it."""
    assert identity.is_legacy_vulnerability_title("log4j-core", "log4j-core") is False


def test_does_not_match_a_license_title():
    assert identity.is_legacy_vulnerability_title(
        "License Policy Violation detected in log4j-core", "log4j-core") is False


def test_recognises_the_shipped_cve_title():
    assert identity.is_legacy_cve_title(
        "CVE-2021-44228 (High) detected in log4j-core",
        "CVE-2021-44228", "log4j-core") is True


def test_cve_legacy_matches_any_severity_word():
    assert identity.is_legacy_cve_title(
        "CVE-2021-44228 (Medium) detected in log4j-core",
        "CVE-2021-44228", "log4j-core") is True


def test_cve_legacy_does_not_match_the_new_title():
    assert identity.is_legacy_cve_title(
        "CVE-2021-44228 detected in log4j-core",
        "CVE-2021-44228", "log4j-core") is False


def test_cve_legacy_does_not_match_a_different_cve():
    assert identity.is_legacy_cve_title(
        "CVE-2021-44228 (High) detected in log4j-core",
        "CVE-2021-45046", "log4j-core") is False


def test_legacy_predicates_tolerate_none_and_empty():
    assert identity.is_legacy_vulnerability_title(None, "log4j-core") is False
    assert identity.is_legacy_vulnerability_title("anything", "") is False
    assert identity.is_legacy_cve_title(None, "CVE-1", "lib") is False
    assert identity.is_legacy_cve_title("anything", "", "lib") is False
