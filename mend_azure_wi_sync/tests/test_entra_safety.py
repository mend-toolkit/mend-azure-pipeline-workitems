"""Two properties no single task owns: the mass-closure interlock, and secret hygiene.

The interlock is the important one. A failed read of the existing work items is
indistinguishable from "this project has nothing open", and acting on that at this
customer's scale is a mass-closure event. Entra adds a NEW way for that read to fail:
credentials that cannot mint a token. It must reach the same abort, not a quiet zero.
"""

from unittest import mock

from mend_azure_wi_sync import core

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def _entra_conf(**overrides):
    values = dict(azure_pat="", azure_tenant_id=TENANT, azure_client_id="cid",
                  azure_client_secret="super-secret-value", proxy={}, ssl_verify="true",
                  azure_uri="https://dev.azure.com/org/", azure_project="Platform",
                  routing="false")
    values.update(overrides)
    return mock.MagicMock(**values)


def test_a_token_failure_does_not_look_like_an_empty_work_item_set():
    """THE test in this file. If get_exist_wi returns an empty dict on an auth failure,
    reconciliation concludes every work item is stale and closes the lot."""
    core.azure_entra_session = {"token": "", "expires_at": 0.0}
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value=""), \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=401, text="")
        result = core.get_exist_wi()
    assert result is None or core.sync_had_fatal_error(), (
        "an auth failure must abort, not return an empty work item set")


def test_the_secret_reaches_no_log_record_at_debug_level(caplog):
    """DEBUG=true is what an operator turns on when it is already failing, which is
    exactly when the credential is most likely to be printed."""
    core.azure_entra_session = {"token": "", "expires_at": 0.0}
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core.requests, "post") as post, \
         caplog.at_level("DEBUG"):
        post.return_value = mock.MagicMock(
            status_code=401,
            text='{"error": "invalid_client", "error_description": "AADSTS7000215"}')
        core.azure_entra_token()
    assert "super-secret-value" not in caplog.text


def test_the_bearer_token_reaches_no_log_record(caplog):
    core.azure_entra_session = {"token": "", "expires_at": 0.0}
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-secret-value"), \
         mock.patch.object(core.requests, "request") as req, \
         caplog.at_level("DEBUG"):
        req.return_value = mock.MagicMock(status_code=200, text='{"value": []}')
        core.call_azure_api("GET", "projects", project="Platform")
    assert "tok-secret-value" not in caplog.text


def test_no_credential_is_reachable_from_custom_field_substitution():
    """conf_json() feeds $MEND_X resolution in analyze_fields / mend_val, and anything
    reachable there can be written into a work item description."""
    from mend_azure_wi_sync.config import Config
    import inspect
    source = inspect.getsource(Config.conf_json)
    for forbidden in ("azure_pat", "azure_client_secret", "azure_tenant_id",
                      "azure_client_id"):
        assert forbidden not in source, f"{forbidden} is reachable from MEND_CUSTOMFIELDS"
