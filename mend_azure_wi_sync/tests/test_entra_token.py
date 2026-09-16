"""Minting the Entra token, and the cache that keeps a long run from re-minting per call.

The cache deadline is measured with time.monotonic(), not time.time(). The client
credentials flow signs nothing with a timestamp so the wall clock does not affect the
mint, but it does affect our own freshness maths: on a self-hosted runner an NTP
correction can step the wall clock mid-run.
"""

from unittest import mock

import requests

from mend_azure_wi_sync import core

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def _conf(**overrides):
    values = dict(azure_pat="", azure_tenant_id=TENANT, azure_client_id="cid",
                  azure_client_secret="sec", proxy={}, ssl_verify="true",
                  azure_uri="https://dev.azure.com/org/", azure_project="Platform")
    values.update(overrides)
    return mock.MagicMock(**values)


def _reset():
    core.azure_entra_session = {"token": "", "expires_at": 0.0}


def test_a_successful_mint_returns_the_access_token():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        assert core.azure_entra_token() == "tok-1"


def test_the_post_goes_to_the_tenant_endpoint_with_a_form_body():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        core.azure_entra_token()
    url = post.call_args[0][0]
    assert url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    body = post.call_args[1]["data"]
    assert body["grant_type"] == "client_credentials"
    assert body["scope"] == "499b84ac-1321-427f-aa17-267ca6975798/.default"


def test_the_token_post_verifies_tls_and_honours_the_proxy():
    """Self-hosted runners sit behind proxies. verify=False here would be a regression
    against the whole point of MEND_SSLVERIFY."""
    _reset()
    proxy = {"http": "http://proxy:8080", "https": "http://proxy:8080"}
    with mock.patch.object(core, "conf", _conf(proxy=proxy)), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        core.azure_entra_token()
    assert post.call_args[1]["verify"] is True
    assert post.call_args[1]["proxies"] == proxy


def test_the_token_is_minted_once_and_then_cached():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        for _ in range(5):
            assert core.azure_entra_token() == "tok-1"
    assert post.call_count == 1


def test_the_token_is_re_minted_once_the_deadline_passes():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post, \
         mock.patch.object(core.time, "monotonic") as clock:
        post.side_effect = [
            mock.MagicMock(status_code=200,
                           text='{"access_token": "tok-1", "expires_in": 3599}'),
            mock.MagicMock(status_code=200,
                           text='{"access_token": "tok-2", "expires_in": 3599}'),
        ]
        clock.return_value = 0.0
        assert core.azure_entra_token() == "tok-1"
        clock.return_value = 3599.0
        assert core.azure_entra_token() == "tok-2"
    assert post.call_count == 2


def test_the_cache_uses_monotonic_time_not_the_wall_clock():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post, \
         mock.patch.object(core.time, "monotonic", return_value=0.0), \
         mock.patch.object(core.time, "time") as wall:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        core.azure_entra_token()
    assert wall.call_count == 0


def test_a_failed_mint_logs_entras_description_and_returns_empty(caplog):
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post, \
         caplog.at_level("ERROR"):
        post.return_value = mock.MagicMock(
            status_code=401,
            text='{"error": "invalid_client", "error_description": '
                 '"AADSTS7000215: Invalid client secret provided."}')
        assert core.azure_entra_token() == ""
    assert "AADSTS7000215" in caplog.text


def test_a_failed_mint_is_not_cached():
    """Otherwise a transient 503 poisons the whole run."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.side_effect = [
            mock.MagicMock(status_code=503, text="{}"),
            mock.MagicMock(status_code=200,
                           text='{"access_token": "tok-1", "expires_in": 3599}'),
        ]
        assert core.azure_entra_token() == ""
        assert core.azure_entra_token() == "tok-1"


def test_a_tls_failure_points_the_operator_at_requests_ca_bundle(caplog):
    """The one failure a TLS-inspecting proxy causes, and the operator must not be left
    reading a handshake traceback."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post",
                           side_effect=requests.exceptions.SSLError("bad cert")), \
         caplog.at_level("ERROR"):
        assert core.azure_entra_token() == ""
    assert "REQUESTS_CA_BUNDLE" in caplog.text


def test_a_connection_failure_returns_empty_rather_than_raising(caplog):
    """A blocked egress to login.microsoftonline.com must not crash the run with a
    traceback; it must fail the way every other transport here fails."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post",
                           side_effect=requests.exceptions.ConnectionError("refused")), \
         caplog.at_level("ERROR"):
        assert core.azure_entra_token() == ""


def test_the_secret_is_never_logged(caplog):
    _reset()
    with mock.patch.object(core, "conf", _conf(azure_client_secret="super-secret-value")), \
         mock.patch.object(core.requests, "post") as post, \
         caplog.at_level("DEBUG"):
        post.return_value = mock.MagicMock(status_code=401, text='{"error": "bad"}')
        core.azure_entra_token()
    assert "super-secret-value" not in caplog.text


def test_invalidating_forces_the_next_call_to_re_mint():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.side_effect = [
            mock.MagicMock(status_code=200,
                           text='{"access_token": "tok-1", "expires_in": 3599}'),
            mock.MagicMock(status_code=200,
                           text='{"access_token": "tok-2", "expires_in": 3599}'),
        ]
        assert core.azure_entra_token() == "tok-1"
        core.invalidate_azure_entra_token()
        assert core.azure_entra_token() == "tok-2"


def test_the_token_post_carries_a_timeout():
    """login.microsoftonline.com is a host the customer's firewall has never had to
    allow. A blackholed egress, dropped rather than refused, hangs the scheduled pipeline
    until the agent job timeout and emits no log line at all."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(
            status_code=200, text='{"access_token": "tok-1", "expires_in": 3599}')
        core.azure_entra_token()
    assert post.call_args[1]["timeout"] == core.ENTRA_TOKEN_TIMEOUT
    assert 0 < core.ENTRA_TOKEN_TIMEOUT <= 30


def test_a_token_post_timeout_returns_empty_and_names_the_host(caplog):
    """The existing except arm already carries the egress and proxy hint; this proves a
    timeout reaches it rather than propagating."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post",
                           side_effect=requests.exceptions.ConnectTimeout("timed out")), \
         caplog.at_level("ERROR"):
        assert core.azure_entra_token() == ""
    assert "login.microsoftonline.com" in caplog.text
