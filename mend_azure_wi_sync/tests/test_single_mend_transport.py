"""Teardown guard for the Mend 2.0 transport.

This tool used to speak three Mend API generations: 1.4 (POST /api/v1.4, userKey + orgToken
in the body), 2.0 (/entities, JWT from an email login) and 3.0 (findings). Enrichment and
routing were the only two 2.0/3.0 consumers and both now read 1.4, so nothing is left to
authenticate with an email via the 2.0 transport. This module asserts that teardown stayed
done. Note: MEND_EMAIL and MEND_APIURL were restored (2026-08-21, plan2-mend-3.0-transport
Task 1) as config for the upcoming 3.0 client -- they are no longer 2.0-only, so this module
no longer asserts their absence.
"""
from mend_azure_wi_sync import core


def test_only_one_mend_transport_remains():
    for gone in ("call_ws_api_v2", "_get_v2", "_post_v2_login", "mend_v2_token",
                 "mend_v2_session", "_fetch_entities_rows", "_resolve_project_names",
                 "entities_rows", "resolved_project_names"):
        assert not hasattr(core, gone), f"{gone} should have been deleted"
    assert hasattr(core, "call_ws_api")
