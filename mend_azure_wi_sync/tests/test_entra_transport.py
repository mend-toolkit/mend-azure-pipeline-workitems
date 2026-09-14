"""The bearer token reaching Azure DevOps, at both of call_azure_api's request sites.

call_azure_api builds a request twice: the main call, and the rebuild in the
JSONDecodeError branch that retries through an HTTP proxy. A fix applied only to the
first leaves a bug that appears solely behind a proxy, which is where self-hosted
runners live.
"""

from unittest import mock

from mend_azure_wi_sync import core

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def _entra_conf(**overrides):
    values = dict(azure_pat="", azure_tenant_id=TENANT, azure_client_id="cid",
                  azure_client_secret="sec", proxy={}, ssl_verify="true",
                  azure_uri="https://dev.azure.com/org/", azure_project="Platform")
    values.update(overrides)
    return mock.MagicMock(**values)


def _pat_conf(**overrides):
    return _entra_conf(azure_pat="a-pat", azure_tenant_id="", azure_client_id="",
                       azure_client_secret="", **overrides)


def _ok(text='{"value": []}'):
    return mock.MagicMock(status_code=200, text=text)


def test_pat_mode_sends_basic_auth_and_no_bearer():
    """No regression for every existing customer."""
    with mock.patch.object(core, "conf", _pat_conf()), \
         mock.patch.object(core.requests, "request", return_value=_ok()) as req:
        core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_args[1]["auth"] == ("", "a-pat")
    assert "Authorization" not in req.call_args[1]["headers"]


def test_entra_mode_sends_a_bearer_and_no_basic_auth():
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request", return_value=_ok()) as req:
        core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_args[1]["headers"]["Authorization"] == "Bearer tok-1"
    assert "auth" not in req.call_args[1]


def test_the_content_type_header_survives_in_entra_mode():
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request", return_value=_ok()) as req:
        core.call_azure_api("PATCH", "wit/workitems/1", header="application/json-patch+json")
    assert req.call_args[1]["headers"]["Content-Type"] == "application/json-patch+json"


def test_the_proxy_retry_path_also_carries_the_bearer():
    """The trap. The JSONDecodeError branch REBUILDS the request; a fix applied only to
    the first site leaves a bug that appears solely behind a proxy."""
    proxy = {"http": "http://proxy:8080", "https": "http://proxy:8080"}
    with mock.patch.object(core, "conf", _entra_conf(proxy=proxy)), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request") as req:
        req.side_effect = [_ok(text="<html>proxy interstitial</html>"), _ok()]
        core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_count == 2
    assert req.call_args_list[1][1]["headers"]["Authorization"] == "Bearer tok-1"


def test_a_401_in_entra_mode_re_mints_once_and_replays():
    """A cached token can die early: clock skew, or a secret rotated mid-run."""
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", side_effect=["tok-1", "tok-2"]), \
         mock.patch.object(core, "invalidate_azure_entra_token") as drop, \
         mock.patch.object(core.requests, "request") as req:
        req.side_effect = [mock.MagicMock(status_code=401, text="{}"), _ok()]
        core.call_azure_api("GET", "projects", project="Platform")
    assert drop.call_count == 1
    assert req.call_count == 2
    assert req.call_args_list[1][1]["headers"]["Authorization"] == "Bearer tok-2"


def test_a_second_401_does_not_loop():
    """A genuine permission failure must surface, not spin."""
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=401, text="")
        _, errorcode = core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_count == 2
    assert errorcode == 2


def test_a_401_in_pat_mode_does_not_re_mint():
    with mock.patch.object(core, "conf", _pat_conf()), \
         mock.patch.object(core, "invalidate_azure_entra_token") as drop, \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=401, text="")
        core.call_azure_api("GET", "projects", project="Platform")
    assert drop.call_count == 0
    assert req.call_count == 1


def test_the_401_message_names_the_credential_actually_in_use():
    """In Entra mode "PAT does not have enough permissions" sends the operator to the
    wrong place. The usual cause is the service principal's org membership or licence."""
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=401, text="")
        res, _ = core.call_azure_api("GET", "projects", project="Platform")
    rendered = str(res)
    assert "service principal" in rendered
    assert "PAT does not have enough permissions" not in rendered

def test_an_empty_token_never_reaches_azure_devops(caplog):
    """azure_entra_token returns "" on mint failure by design. Sending `Bearer ` with
    nothing after it is not reliably a 401: Azure DevOps can answer 203, or redirect to a
    sign-in page that requests follows to a 200 HTML body, which lands in the
    JSONDecodeError branch and exit(-1)s with a proxy message for a token-mint failure."""
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value=""), \
         mock.patch.object(core.requests, "request") as req, \
         caplog.at_level("ERROR"):
        res, errorcode = core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_count == 0, "no request may go out carrying an empty bearer"
    assert errorcode == 2
    assert "token" in str(res).lower()


def test_an_empty_token_does_not_exit_the_process():
    """errorcode 2 is what get_exist_wi and the sync guards already treat as a fatal read
    failure, so the mass-closure invariant holds without a hard exit."""
    with mock.patch.object(core, "conf", _entra_conf()), \
         mock.patch.object(core, "azure_entra_token", return_value=""), \
         mock.patch.object(core.requests, "request"):
        _, errorcode = core.call_azure_api("GET", "projects", project="Platform")
    assert errorcode == 2


def test_a_pat_run_is_untouched_by_the_empty_token_guard():
    with mock.patch.object(core, "conf", _pat_conf()), \
         mock.patch.object(core.requests, "request", return_value=_ok()) as req:
        _, errorcode = core.call_azure_api("GET", "projects", project="Platform")
    assert req.call_count == 1
    assert errorcode == 0
