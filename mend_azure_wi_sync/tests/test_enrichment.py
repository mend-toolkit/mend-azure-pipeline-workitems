from mend_azure_wi_sync import enrichment as en


def test_format_reachability_covers_every_state():
    for raw, shown in [("REACHABLE", "Reachable"),
                       ("UNREACHABLE", "Unreachable")]:
        assert en.format_reachability({"reachability": raw}) == shown
    assert en.format_reachability({}) == en.NO_DATA
    assert en.format_reachability({"reachability": "FUTURE_VALUE"}) == "FUTURE_VALUE"


def test_format_epss_does_not_rescale_the_value():
    """epssPercentage arrives on a 0-100 scale — it is already a percentage.

    Confirmed against live Mend data 2026-08-19, correcting an earlier assumption that it
    was a 0-1 probability. Multiplying by 100 rendered every score 100x too high: a real
    0.8% read as 80.0%, which in a triage field is the difference between "ignore this"
    and "drop everything".
    """
    def _epss(raw):
        return en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": raw}}})

    assert _epss(92.4) == "92.4%"
    assert _epss(100) == "100.0%"
    assert _epss(2.5) == "2.5%"
    assert _epss(1) == "1.0%"          # the boundary is inclusive: 1 is not "below 1%"


def test_format_epss_renders_anything_below_one_percent_as_less_than_one():
    """Matches Mend's own repo integration, which is the point: the same score must not read
    differently depending on which Mend surface a triager is looking at.

    One decimal on a 0-100 scale would compress most of the real distribution -- the majority
    of CVEs score well under 1% -- into a wall of "0.0%" and "0.3%". Verified live 2026-08-21:
    epssPercentage 0.253 is 0.25% in the Mend UI, which one decimal renders "0.3%".
    """
    def _epss(raw):
        return en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": raw}}})

    assert _epss(0.253) == "<1%"       # the live sample; the UI shows 0.25%
    assert _epss(0.8) == "<1%"
    assert _epss(0.04) == "<1%"
    assert _epss(0.924) == "<1%"
    assert _epss(0.999) == "<1%"


def test_format_epss_renders_zero_as_a_real_score():
    # 0.0 is a valid EPSS score and is falsy. A truthiness check here would render a real
    # answer as "we got nothing" -- "<1%" is a real answer, en.NO_DATA is not.
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": 0.0}}}) == "<1%"
    assert en.format_epss({}) == en.NO_DATA
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": "x"}}}) == en.NO_DATA


def test_format_epss_survives_an_overflowing_value():
    # MINOR 7: float() of a very large JSON integer raises OverflowError, not ValueError,
    # and this formatter is called unguarded from inside create_wi.
    huge = 10 ** 400
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": huge}}}) == en.NO_DATA


def test_format_exploit_reads_maturity_and_falls_back_to_no_data():
    # The `exploitable` boolean fallback is gone -- see
    # test_format_exploit_no_longer_falls_back_to_the_exploitable_boolean below.
    assert en.format_exploit({"vulnerability": {"threatAssessment": {"exploitCodeMaturity": "POC_CODE"}}}) == "PoC Code"
    assert en.format_exploit({"vulnerability": {"threatAssessment": {"exploitCodeMaturity": "NOT_DEFINED"}}}) == "Not Defined"
    assert en.format_exploit({}) == en.NO_DATA


def test_format_exploit_no_longer_falls_back_to_the_exploitable_boolean():
    """Alerts carry exploitCodeMaturity and no `exploitable` field, and maturity is the signal
    Mend's own repo integration displays. The boolean fallback is dead once enrichment reads
    alerts, and a dead fallback in a triage renderer is worse than no fallback: it would render
    a stale 3.0-shaped value if one ever survived in a payload."""
    assert en.format_exploit({"exploitable": True}) == en.NO_DATA
    assert en.format_exploit({"exploitable": False}) == en.NO_DATA
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": "FUNCTIONAL"}}}) == "Functional"


def test_reachability_labels_carry_only_the_two_live_values():
    assert set(en.REACHABILITY_LABELS) == {"REACHABLE", "UNREACHABLE"}
