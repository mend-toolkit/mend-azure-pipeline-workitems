from mend_azure_wi_sync import core
from mend_azure_wi_sync import enrichment as en


def test_reachability_stays_gated_when_its_flag_is_off():
    # Reachability is blank for an org that has not enabled reachability analysis, so the
    # toggle spares them a column of dashes in every row.
    assert core.reachability_row_field({}, reachability_on=False) == {}


def test_epss_exploit_row_fields_are_no_longer_gated():
    """Both values arrive inline with the 3.0 finding and always carry a value, so there is
    nothing left for MEND_EPSS to gate."""
    fields = core.epss_exploit_row_fields(
        {"vulnerability": {"threatAssessment": {"epssPercentage": 5.0,
                                                "exploitCodeMaturity": "HIGH"}}})
    assert set(fields) == {"EPSS", "Exploit"}
    assert set(core.epss_exploit_row_fields({})) == {"EPSS", "Exploit"}


def test_reachability_row_field_only_gated_on_the_reachability_flag():
    fields = core.reachability_row_field(
        {"reachabilityInfo": {"reachable": True, "analyzed": True}}, reachability_on=True)
    assert set(fields) == {"Reachability"}


def test_build_enrich_html_renders_epss_always_and_reachability_on_its_flag():
    """EPSS and Exploit Code Maturity are ungated; Reachability is the only switch left."""
    policy_el = {"vulnerability": {"threatAssessment": {"epssPercentage": 5.0,
                                                        "exploitCodeMaturity": "HIGH"}},
                "reachabilityInfo": {"reachable": True, "analyzed": True}}

    off = core.build_enrich_html(policy_el, reachability_on=False)
    assert "<b>EPSS:</b>" in off
    assert "<b>Exploit Code Maturity:</b>" in off
    assert "<b>Reachability:</b>" not in off

    both = core.build_enrich_html(policy_el, reachability_on=True)
    assert "<b>Reachability:</b>" in both
    assert "<b>EPSS:</b>" in both
    assert "<b>Exploit Code Maturity:</b>" in both
    # Reachability renders first, matching the row's column order.
    assert both.index("<b>Reachability:</b>") < both.index("<b>EPSS:</b>")


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
