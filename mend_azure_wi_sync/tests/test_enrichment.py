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
    candidates, matched, max_epss = en.decorate_policy_violations(libs, idx)
    hit, miss = libs[0]["policyViolations"]
    assert hit["reachability"] == "REACHABLE"
    assert hit["vulnerability"]["threatAssessment"]["epssPercentage"] == 0.92
    assert "reachability" not in miss
    assert "threatAssessment" not in miss["vulnerability"]
    assert (candidates, matched, max_epss) == (2, 1, 0.92)


def test_decorate_never_creates_a_vulnerability_key():
    # A license policy violation has no vulnerability. Inventing one would render
    # vulnerability fields on a Work Item that describes a license.
    libs = [{"library": {"keyUuid": "lib-a"}, "policyViolations": [{}]}]
    en.decorate_policy_violations(libs, en.build_index([_finding("CVE-1", "lib-a")]))
    assert libs[0]["policyViolations"][0] == {}


def test_decorate_survives_malformed_input():
    assert en.decorate_policy_violations([{}, {"policyViolations": None}], {}) == (0, 0, None)


def test_format_reachability_covers_every_state():
    for raw, shown in [("REACHABLE", "Reachable"),
                       ("POTENTIALLY_REACHABLE", "Potentially Reachable"),
                       ("UNREACHABLE", "Unreachable"),
                       ("REACHABILITY_UNAVAILABLE", "Reachability Unavailable")]:
        assert en.format_reachability({"reachability": raw}) == shown
    assert en.format_reachability({}) == en.NO_DATA
    assert en.format_reachability({"reachability": "FUTURE_VALUE"}) == "FUTURE_VALUE"


def test_format_epss_renders_zero_as_a_real_score():
    # 0.0 is a valid EPSS score and is falsy. A truthiness check here would render a real
    # answer as "we got nothing".
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": 0.0}}}) == "0.0%"
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": 0.924}}}) == "92.4%"
    assert en.format_epss({}) == en.NO_DATA
    assert en.format_epss({"vulnerability": {"threatAssessment": {"epssPercentage": "x"}}}) == en.NO_DATA


def test_format_exploit_distinguishes_no_from_nothing():
    assert en.format_exploit({"vulnerability": {"threatAssessment": {"exploitCodeMaturity": "POC_CODE"}}}) == "PoC Code"
    assert en.format_exploit({"vulnerability": {"threatAssessment": {"exploitCodeMaturity": "NOT_DEFINED"}}}) == "Not Defined"
    assert en.format_exploit({"exploitable": True}) == "Yes"
    assert en.format_exploit({"exploitable": False}) == "No"
    assert en.format_exploit({}) == en.NO_DATA
