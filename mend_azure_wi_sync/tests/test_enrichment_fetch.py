from mend_azure_wi_sync import core
from mend_azure_wi_sync import enrichment as en


def test_the_alerts_fetch_and_join_are_gone():
    """Enrichment values now arrive on the 3.0 finding itself (source3.render_inputs calls the
    formatters directly), so there is no second Mend call to make and nothing to join. These
    names existing again means a 1.4 fetch crept back in."""
    for gone in ("fetch_project_alerts", "enrich_project", "safe_decorate",
                 "alerts_enabled", "requested_signal_names", "ALERTS_WARNED"):
        assert not hasattr(core, gone), f"core.{gone} should have been deleted"
    for gone in ("build_alert_index", "decorate_policy_violations", "extract_alert_values",
                 "_reachability_from_info"):
        assert not hasattr(en, gone), f"enrichment.{gone} should have been deleted"


def test_the_1_4_client_is_gone():
    """call_ws_api was the single 1.4 transport. Nothing in the run speaks 1.4 any more."""
    assert not hasattr(core, "call_ws_api")
    assert not hasattr(core, "API_VERSION")


def test_the_2_0_and_3_0_transports_are_gone():
    """Guards an earlier deletion. These names existing again means the consolidation
    regressed.

    call_ws_api_v3 is deliberately excluded from this list: it was restored when the
    single-transport goal was reversed, so its presence is no longer a regression. See
    test_mend_v3_auth.py for its coverage.
    """
    for gone in ("fetch_project_enrichment", "resolve_project_uuids",
                 "prepare_enrichment", "project_uuid_map", "enrichment_disabled",
                 "ENRICHMENT_PAGE_LIMIT", "ENRICHMENT_MAX_PAGES",
                 "_fetch_entities_rows", "_resolve_project_names",
                 "entities_rows", "resolved_project_names"):
        assert not hasattr(core, gone), f"{gone} should have been deleted"

    # The formatters and their labels SURVIVE: source3.render_inputs calls them, and
    # format_epss encodes the 0-100 EPSS scale fix.
    for kept in ("format_epss", "format_exploit", "format_reachability",
                 "NO_DATA", "EPSS_BELOW_ONE", "REACHABILITY_LABELS", "MATURITY_LABELS"):
        assert hasattr(en, kept), f"enrichment.{kept} must survive"
