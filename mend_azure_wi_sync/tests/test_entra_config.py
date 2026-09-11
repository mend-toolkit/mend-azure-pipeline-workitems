"""The Entra config surface, and the credential leak it must not widen.

conf_json() feeds MEND_CUSTOMFIELDS substitution ($MEND_X in analyze_fields / mend_val).
Anything reachable from there can be written into a work item description and read by
everyone with board access. The PAT was reachable; nothing credential-bearing is now.
"""

import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import Config

VALID = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def _conf(**overrides):
    """Mirrors tests/test_routing_config.py:_valid_conf. It deliberately omits every
    defaulted field, which is exactly why the three new fields must have defaults."""
    fields = dict(ws_user_key=VALID, ws_url="https://saas.mend.io",
                  azure_uri="https://dev.azure.com/org/", azure_project="Platform",
                  azure_pat=VALID, utc_delta=0, wsproducttoken="",
                  wsprojecttoken="", wsexcludetoken="", azure_area="", azure_type="Task",
                  azure_custom="", dependency="true", reponame="", description="ReproSteps",
                  priority="false", proxy="", routing="false",
                  branches="main,master", reachability="false",
                  email="qa@example.com", org_uuid=VALID, severity="high",
                  closed_state="Closed", reopen_state="New")
    fields.update(overrides)
    return Config(**fields)


def test_the_three_entra_fields_default_to_empty():
    """They MUST be defaulted, not positional. A required field raises TypeError in every
    helper that builds Config from an explicit dict, including this one."""
    conf = _conf()
    assert conf.azure_tenant_id == ""
    assert conf.azure_client_id == ""
    assert conf.azure_client_secret == ""


def test_the_fields_round_trip_when_set():
    conf = _conf(azure_tenant_id=TENANT, azure_client_id="cid", azure_client_secret="sec")
    assert (conf.azure_tenant_id, conf.azure_client_id, conf.azure_client_secret) == (
        TENANT, "cid", "sec")


def test_conf_json_no_longer_exposes_the_pat():
    """Live defect until this change: $MEND_AZUREPAT in MEND_CUSTOMFIELDS wrote the PAT
    into a work item description."""
    assert "wsazurepat" not in _conf().conf_json()


def test_conf_json_exposes_no_entra_credential():
    conf = _conf(azure_tenant_id=TENANT, azure_client_id="cid", azure_client_secret="sec")
    exposed = conf.conf_json()
    assert "sec" not in exposed.values()
    for key in ("wsazuretenantid", "wsazureclientid", "wsazureclientsecret"):
        assert key not in exposed


def test_no_conf_json_value_carries_the_secret():
    """Belt and braces: catches a future key added under any name."""
    conf = _conf(azure_tenant_id=TENANT, azure_client_id="cid",
                 azure_client_secret="super-secret-value")
    assert "super-secret-value" not in repr(conf.conf_json())


def test_an_unexpanded_pipeline_placeholder_is_blanked():
    """If Azure does not substitute $(MEND_AZURECLIENTSECRET), the literal must become ""
    so check_patterns reports a missing secret. Otherwise the tool POSTs the placeholder
    to Entra and the operator debugs AADSTS7000215 instead of a pipeline variable."""
    conf = _conf(azure_tenant_id="$(MEND_AZURETENANTID)",
                 azure_client_id="$(MEND_AZURECLIENTID)",
                 azure_client_secret="$(MEND_AZURECLIENTSECRET)")
    conf.update_properties()
    assert conf.azure_tenant_id == ""
    assert conf.azure_client_id == ""
    assert conf.azure_client_secret == ""


def test_startup_reads_all_three_variables():
    env = {"MEND_AZURETENANTID": TENANT, "MEND_AZURECLIENTID": "cid",
           "MEND_AZURECLIENTSECRET": "sec", "MEND_URL": "https://saas.mend.io",
           "MEND_USERKEY": VALID, "MEND_ORGUUID": VALID, "MEND_EMAIL": "qa@example.com",
           "MEND_AZUREURI": "https://dev.azure.com/org/", "MEND_AZUREPROJECT": "Platform"}
    with mock.patch.dict(os.environ, env, clear=False):
        conf = core.startup()
    assert conf.azure_tenant_id == TENANT
    assert conf.azure_client_id == "cid"
    assert conf.azure_client_secret == "sec"
