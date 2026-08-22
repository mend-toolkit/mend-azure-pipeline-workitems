from mend_azure_wi_sync import identity


def test_matches_the_shipped_dependency_title():
    assert identity.matches_library(
        "log4j-core: 3 vulnerabilities (highest severity is 9.8)", "log4j-core") is True


def test_matches_whatever_the_count_and_score_are():
    """The whole point: the count and score are wildcards, so they can change freely."""
    assert identity.matches_library(
        "log4j-core: 1 vulnerabilities (highest severity is )", "log4j-core") is True
    assert identity.matches_library(
        "log4j-core: 47 vulnerabilities (highest severity is 10.0)", "log4j-core") is True


def test_a_suppressed_vulnerability_still_matches_the_same_item():
    """Regression for the defect this exists to fix: 3 -> 2 must still match."""
    before = "log4j-core: 3 vulnerabilities (highest severity is 9.8)"
    after = "log4j-core: 2 vulnerabilities (highest severity is 7.5)"
    assert identity.matches_library(before, "log4j-core") is True
    assert identity.matches_library(after, "log4j-core") is True


def test_does_not_match_a_different_library():
    """'log4j' must not claim 'log4j-core''s work item."""
    assert identity.matches_library(
        "log4j-core: 3 vulnerabilities (highest severity is 9.8)", "log4j") is False


def test_does_not_match_a_longer_library_name():
    assert identity.matches_library(
        "log4j: 3 vulnerabilities (highest severity is 9.8)", "log4j-core") is False


def test_does_not_match_a_license_title():
    assert identity.matches_library(
        "License Policy Violation detected in log4j-core", "log4j-core") is False


def test_does_not_match_a_per_cve_title():
    assert identity.matches_library(
        "CVE-2021-44228 (High) detected in log4j-core", "log4j-core") is False


def test_tolerates_none_and_empty_without_raising():
    assert identity.matches_library(None, "log4j-core") is False
    assert identity.matches_library("anything", "") is False
    assert identity.matches_library("", "log4j-core") is False


def test_a_regex_metacharacter_in_the_library_name_is_literal():
    """A library named 'a.b' must not match a title for 'aXb'."""
    assert identity.matches_library(
        "aXb: 3 vulnerabilities (highest severity is 9.8)", "a.b") is False
    assert identity.matches_library(
        "a.b: 3 vulnerabilities (highest severity is 9.8)", "a.b") is True


def test_license_title_is_unchanged_from_the_shipped_format():
    assert identity.license_title("log4j-core") == \
        "License Policy Violation detected in log4j-core"


def test_deleted_helpers_are_gone():
    """Nothing may still depend on the title-composition helpers."""
    for gone in ("vulnerability_title", "cve_title",
                 "is_legacy_vulnerability_title", "is_legacy_cve_title"):
        assert not hasattr(identity, gone), f"{gone} should have been deleted"
