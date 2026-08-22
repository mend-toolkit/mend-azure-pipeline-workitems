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
