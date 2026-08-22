from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import enrichment as en


def test_no_enrichment_keys_are_added_when_both_flags_are_off():
    # MEND_EPSS and MEND_REACHABILITY both default to false. Existing users must see a
    # byte-identical work item -- not three columns of "-".
    assert core.epss_exploit_row_fields({}, epss_on=False) == {}
    assert core.reachability_row_field({}, reachability_on=False) == {}


def test_epss_exploit_row_fields_only_gated_on_the_epss_flag():
    """EPSS/Exploit must be independent of reachability -- an org may not have reachability
    analysis enabled at all."""
    fields = core.epss_exploit_row_fields(
        {"vulnerability": {"threatAssessment": {"epssPercentage": 5.0,
                                                "exploitCodeMaturity": "HIGH"}}},
        epss_on=True)
    assert set(fields) == {"EPSS", "Exploit"}


def test_reachability_row_field_only_gated_on_the_reachability_flag():
    fields = core.reachability_row_field(
        {"reachabilityInfo": {"reachable": True, "analyzed": True}}, reachability_on=True)
    assert set(fields) == {"Reachability"}


def test_build_enrich_html_covers_all_four_flag_combinations():
    """Both MEND_DEPENDENCY branches splice `enrich_html` into vul_data via this one
    function, so each of the four flag combinations must render only its own lines and
    nothing else."""
    policy_el = {"vulnerability": {"threatAssessment": {"epssPercentage": 5.0,
                                                        "exploitCodeMaturity": "HIGH"}},
                "reachabilityInfo": {"reachable": True, "analyzed": True}}

    neither = core.build_enrich_html(policy_el, epss_on=False, reachability_on=False)
    assert neither == ""

    epss_only = core.build_enrich_html(policy_el, epss_on=True, reachability_on=False)
    assert "<b>EPSS:</b>" in epss_only
    assert "<b>Exploit Code Maturity:</b>" in epss_only
    assert "<b>Reachability:</b>" not in epss_only

    reachability_only = core.build_enrich_html(policy_el, epss_on=False, reachability_on=True)
    assert "<b>Reachability:</b>" in reachability_only
    assert "<b>EPSS:</b>" not in reachability_only
    assert "<b>Exploit Code Maturity:</b>" not in reachability_only

    both = core.build_enrich_html(policy_el, epss_on=True, reachability_on=True)
    assert "<b>Reachability:</b>" in both
    assert "<b>EPSS:</b>" in both
    assert "<b>Exploit Code Maturity:</b>" in both
    # Reachability renders first, matching the row's column order.
    assert both.index("<b>Reachability:</b>") < both.index("<b>EPSS:</b>")


def test_decoration_failure_cannot_cost_work_items():
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    # Patch on `core`, not on `enrichment`: core binds the name at import time, so patching
    # the source module would leave core's reference untouched and this test would pass
    # while testing nothing.
    with mock.patch.object(core, "decorate_policy_violations", side_effect=TypeError("boom")):
        assert core.safe_decorate(libs, {}) is None


def test_decoration_failure_after_the_call_also_cannot_cost_work_items():
    # safe_decorate's whole body must be guarded, not just the decorate_policy_violations
    # call: an arity change in its return value must not raise into create_wi either.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with mock.patch.object(core, "decorate_policy_violations", return_value=(1,)):  # wrong arity
        assert core.safe_decorate(libs, {}) is None


def test_safe_decorate_warns_only_when_candidates_matched_nothing(caplog):
    # The alerts index carries every open alert in the project while candidates is only
    # this window's policy violations, so warning on "0 of N findings" would fire on most
    # projects every run and train operators to ignore the one signal that detects a
    # broken join.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, {})
    assert any("matched" in r.message for r in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING"):
        core.safe_decorate([], {("CVE-1", "lib-a"): {}})
    assert not caplog.records


def test_a_normal_epss_score_does_not_warn(caplog):
    """The EPSS unit question is settled: epssPercentage is 0-100, confirmed against live
    Mend data 2026-08-19.

    The old `> 1` warning existed only to detect the unit being a percentage. Now that it
    IS a percentage, values above 1 are ordinary — every genuinely exploited CVE has one —
    so a warning there would fire constantly and say something false.
    """
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, {("CVE-1", "lib-a"): {"epss": 92.4}})
    assert not [r for r in caplog.records if "100x" in r.message]


def test_format_reachability_ignores_a_non_string_leaf():
    # dict.get() raises TypeError: unhashable type on a dict/list key. _get only guarantees
    # the CONTAINER is a dict, never the leaf type, and this formatter is called unguarded
    # from inside create_wi -- an exception here would silently drop every work item for
    # the project while the run still reported success.
    assert en.format_reachability({"reachability": {"unexpected": "object"}}) == en.NO_DATA
    assert en.format_reachability({"reachability": ["unexpected"]}) == en.NO_DATA


def test_format_exploit_ignores_a_non_string_leaf():
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": {"unexpected": "object"}}}}
    ) == en.NO_DATA
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": ["unexpected"]}}}
    ) == en.NO_DATA
