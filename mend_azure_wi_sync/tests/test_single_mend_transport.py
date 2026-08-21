"""Teardown guard for the Mend 2.0 transport.

This tool used to speak three Mend API generations: 1.4 (POST /api/v1.4, userKey + orgToken
in the body), 2.0 (/entities, JWT from an email login) and 3.0 (findings). Enrichment and
routing were the only two 2.0/3.0 consumers and both now read 1.4, so nothing is left to
authenticate with an email. This module asserts the teardown stayed done -- reintroducing any
of these names would also reintroduce MEND_EMAIL / MEND_APIURL as required config.
"""
from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import Config, varenvs


def test_only_one_mend_transport_remains():
    for gone in ("call_ws_api_v2", "_get_v2", "_post_v2_login", "mend_v2_token",
                 "mend_v2_session", "_fetch_entities_rows", "_resolve_project_names",
                 "entities_rows", "resolved_project_names"):
        assert not hasattr(core, gone), f"{gone} should have been deleted"
    assert hasattr(core, "call_ws_api")


def test_the_2_0_config_variables_are_gone():
    """MEND_EMAIL and MEND_APIURL existed only to build the 2.0 login. Leaving either in
    varenvs would keep them documented-by-code and re-invite a validation for them."""
    for gone in ("wsemail", "wsapiurl"):
        assert not hasattr(varenvs, gone), f"varenvs.{gone} should have been deleted"
    for gone in ("email", "api_url"):
        assert gone not in Config.__annotations__, f"Config.{gone} should have been deleted"
