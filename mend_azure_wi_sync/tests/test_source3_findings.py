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
