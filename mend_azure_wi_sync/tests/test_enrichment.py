from mend_azure_wi_sync import enrichment as en


def _finding(name="CVE-1", uuid="lib-1", reach="REACHABLE", epss=0.92,
             maturity="FUNCTIONAL", exploitable=True):
    return {"name": name, "component": {"uuid": uuid}, "reachability": reach,
            "exploitable": exploitable,
            "threatAssessment": {"epssPercentage": epss,
                                 "exploitCodeMaturity": maturity}}


def test_extract_values_reads_the_finding_level_threat_assessment():
    assert en.extract_values(_finding()) == {
        "reachability": "REACHABLE", "epss": 0.92,
        "maturity": "FUNCTIONAL", "exploitable": True}


def test_extract_values_falls_back_to_the_nested_vulnerability_threat_assessment():
    f = {"name": "CVE-1", "component": {"uuid": "lib-1"},
         "vulnerability": {"threatAssessment": {"epssPercentage": 0.5,
                                               "exploitCodeMaturity": "HIGH"}}}
    assert en.extract_values(f) == {"epss": 0.5, "maturity": "HIGH"}


def test_extract_values_omits_keys_mend_did_not_send():
    # Absent must stay absent: the formatters distinguish "Mend said nothing" from
    # "Mend said no", and a None sentinel would erase that distinction.
    assert en.extract_values({"name": "CVE-1", "component": {"uuid": "l"}}) == {}


def test_extract_values_keeps_falsy_but_real_answers():
    f = _finding(epss=0.0, exploitable=False, maturity="NOT_DEFINED")
    values = en.extract_values(f)
    assert values["epss"] == 0.0
    assert values["exploitable"] is False
    assert values["maturity"] == "NOT_DEFINED"


def test_build_index_keys_on_cve_and_library_uuid():
    idx = en.build_index([_finding("CVE-1", "lib-a"), _finding("CVE-1", "lib-b")])
    assert set(idx) == {("CVE-1", "lib-a"), ("CVE-1", "lib-b")}


def test_build_index_skips_findings_missing_either_key():
    assert en.build_index([{"name": "CVE-1"}, {"component": {"uuid": "l"}}]) == {}


def _libs():
    return [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}},
                                  {"vulnerability": {"name": "CVE-2"}}]}]


def test_decorate_writes_values_onto_matching_violations_only():
    libs = _libs()
    idx = en.build_index([_finding("CVE-1", "lib-a")])
    candidates, matched = en.decorate_policy_violations(libs, idx)
    hit, miss = libs[0]["policyViolations"]
    assert hit["reachability"] == "REACHABLE"
    assert hit["vulnerability"]["threatAssessment"]["epssPercentage"] == 0.92
    assert "reachability" not in miss
    assert "threatAssessment" not in miss["vulnerability"]
    assert (candidates, matched) == (2, 1)


def test_decorate_merges_threat_assessment_rather_than_replacing_it():
    """MINOR 4: a MEND_CUSTOMFIELDS user reading a sub-path 1.4 already sent under
    threatAssessment must not silently start seeing 'No content' once enrichment decorates
    the same key."""
    libs = [{"library": {"keyUuid": "lib-a"},
            "policyViolations": [{"vulnerability": {
                "name": "CVE-1",
                "threatAssessment": {"someExisting1_4Field": "keep-me"}}}]}]
    en.decorate_policy_violations(libs, en.build_index([_finding("CVE-1", "lib-a")]))
    threat = libs[0]["policyViolations"][0]["vulnerability"]["threatAssessment"]
    assert threat["someExisting1_4Field"] == "keep-me"
    assert threat["epssPercentage"] == 0.92
    assert threat["exploitCodeMaturity"] == "FUNCTIONAL"


def test_decorate_never_creates_a_vulnerability_key():
    # A license policy violation has no vulnerability. Inventing one would render
    # vulnerability fields on a Work Item that describes a license.
    libs = [{"library": {"keyUuid": "lib-a"}, "policyViolations": [{}]}]
    en.decorate_policy_violations(libs, en.build_index([_finding("CVE-1", "lib-a")]))
    assert libs[0]["policyViolations"][0] == {}


def test_decorate_survives_malformed_input():
    assert en.decorate_policy_violations([{}, {"policyViolations": None}], {}) == (0, 0)


def test_an_empty_but_real_match_still_counts_as_matched():
    # index.get returns {} when the join hit but Mend sent no enrichment fields for that
    # finding. Counting it as unmatched would make the caller's "matched 0 of N" warning
    # — which exists to detect a wrong join key — fire on a perfectly correct join.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    candidates, matched = en.decorate_policy_violations(
        libs, {("CVE-1", "lib-a"): {}})
    assert (candidates, matched) == (1, 1)
    assert "reachability" not in libs[0]["policyViolations"][0]


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


def test_reachability_maps_the_analyzed_boolean_pair():
    """Mend's reachability vocabulary is now two values, so the pair collapses to two strings
    plus "we were not told". analyzed=false occurs only when reachability analysis has not run
    (confirmed 2026-08-21), and it deliberately maps to None so the renderer shows NO_DATA."""
    assert en._reachability_from_info({"reachable": True, "analyzed": True}) == "REACHABLE"
    assert en._reachability_from_info({"reachable": False, "analyzed": True}) == "UNREACHABLE"
    assert en._reachability_from_info({"reachable": False, "analyzed": False}) is None
    assert en._reachability_from_info({"reachable": True, "analyzed": False}) is None
    assert en._reachability_from_info({}) is None
    assert en._reachability_from_info(None) is None
    assert en._reachability_from_info("REACHABLE") is None


def test_reachability_needs_a_real_boolean_not_a_truthy_value():
    """A non-boolean `reachable` must not be guessed at: "confidently wrong is worse than
    blank" applies to a triage field."""
    assert en._reachability_from_info({"reachable": "yes", "analyzed": True}) is None
    assert en._reachability_from_info({"reachable": None, "analyzed": True}) is None


def test_extract_alert_values_reads_the_live_payload():
    """Field paths verified live 2026-08-21 against getProjectAlertsByType."""
    alert = {
        "vulnerability": {"name": "CVE-2026-31802",
                          "threatAssessment": {"exploitCodeMaturity": "NOT_DEFINED",
                                               "epssPercentage": 0.253}},
        "reachabilityInfo": {"reachable": False, "analyzed": True},
        "library": {"keyUuid": "9c2fb703-17e5-4f3c-8297-ad9ec3c625b0"},
    }
    assert en.extract_alert_values(alert) == {"reachability": "UNREACHABLE",
                                             "maturity": "NOT_DEFINED",
                                             "epss": 0.253}


def test_extract_alert_values_omits_what_it_did_not_get():
    """The renderers treat an absent key as "we got nothing" and a present one as a real Mend
    answer, so a None must never be stored."""
    assert en.extract_alert_values({}) == {}
    assert en.extract_alert_values({"vulnerability": {"threatAssessment": {}}}) == {}
    assert en.extract_alert_values(
        {"vulnerability": {"threatAssessment": {"epssPercentage": 0.0}}}) == {"epss": 0.0}


def test_build_alert_index_keys_on_cve_and_library_uuid():
    """The join key is (vulnerability.name, library.keyUuid) -- both 1.4 field names, both in
    the same identifier space as fetchProjectPolicyIssues. This is what retires the unverified
    1.4 keyUuid == 3.0 component.uuid assumption: there is no cross-space join left."""
    alerts = [{"vulnerability": {"name": "CVE-1", "threatAssessment": {"epssPercentage": 2.5}},
               "library": {"keyUuid": "lib-a"}},
              {"vulnerability": {"name": "CVE-2", "threatAssessment": {"epssPercentage": 9.0}},
               "library": {"keyUuid": "lib-b"}}]
    assert en.build_alert_index(alerts) == {("CVE-1", "lib-a"): {"epss": 2.5},
                                           ("CVE-2", "lib-b"): {"epss": 9.0}}


def test_build_alert_index_skips_unusable_alerts():
    alerts = ["not-a-dict",
              {"library": {"keyUuid": "lib-a"}},                      # no CVE name
              {"vulnerability": {"name": "CVE-1"}},                   # no library uuid
              {"vulnerability": {"name": "CVE-2"}, "library": {"keyUuid": "lib-b"}},  # no values
              {"vulnerability": {"name": "CVE-3", "threatAssessment": {"epssPercentage": 1.0}},
               "library": {"keyUuid": "lib-c"}}]
    assert en.build_alert_index(alerts) == {("CVE-3", "lib-c"): {"epss": 1.0}}
    assert en.build_alert_index([]) == {}
    assert en.build_alert_index(None) == {}


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
