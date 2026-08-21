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
