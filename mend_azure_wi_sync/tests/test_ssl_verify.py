"""TLS certificate verification is ON, and the warnings go away because there is nothing to warn.

Every transport call hardcoded verify=False, so every run printed urllib3's
InsecureRequestWarning for api-saas.mend.io and dev.azure.com. Nothing here needs a certificate
installed: requests ships the certifi CA bundle and both hosts serve publicly trusted certs, so an
Azure DevOps hosted agent validates them with no configuration at all.

MEND_SSLVERIFY exists for the case this tool cannot see -- a self-hosted runner behind a
TLS-inspecting proxy, where the presented cert is the proxy's. "false" restores the old unverified
behaviour, and a path supplies a CA bundle. Neither is needed on a hosted agent.

When verification IS off, the warning is suppressed once at source rather than logged per call:
the previous code caught and logged it in three transports and MISSED the 2.0 login, which is why
one raw connectionpool.py warning still reached the pipeline's stderr.
"""

from unittest import mock

from mend_azure_wi_sync import core


def _conf(ssl_verify=True, **overrides):
    values = dict(ssl_verify=ssl_verify, proxy={}, azure_project="TestProj", azure_pat="pat",
                  azure_uri="https://dev.azure.com/org", email="a@b.c", ws_user_key="uk",
                  ws_org_token="ot")
    values.update(overrides)
    return mock.MagicMock(**values)


# ------------------------------------------------------------------- reading the config value

def test_unset_means_verify():
    """The secure default has to be what an operator gets by doing nothing."""
    assert core.verify_setting("") is True
    assert core.verify_setting(None) is True


def test_true_and_yes_and_one_all_mean_verify():
    for raw in ("true", "TRUE", "True", "yes", "1", " true "):
        assert core.verify_setting(raw) is True, raw


def test_false_means_do_not_verify():
    for raw in ("false", "FALSE", "no", "0", " false "):
        assert core.verify_setting(raw) is False, raw


def test_a_path_is_passed_through_as_a_ca_bundle():
    assert core.verify_setting("/etc/ssl/corp-ca.pem") == "/etc/ssl/corp-ca.pem"


def test_an_unexpanded_azure_placeholder_falls_back_to_verify():
    """Config.update_properties blanks these, but a placeholder reaching here must not be read as
    a CA bundle path called "$(MEND_SSLVERIFY)"."""
    assert core.verify_setting("$(MEND_SSLVERIFY)") is True


def test_garbage_falls_back_to_verifying_not_to_skipping():
    """A typo must never silently disable TLS validation."""
    assert core.verify_setting("ture") is True
    assert core.verify_setting("maybe") is True


# ------------------------------------------------------- every transport honours the setting

def test_the_mend_login_verifies():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_api_url", return_value="https://api-saas.mend.io"), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(status_code=200, text="{}")
        core._post_v2_login()
    assert post.call_args.kwargs["verify"] is True


def test_the_mend_3_0_get_verifies():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    assert get.call_args.kwargs["verify"] is True


def test_the_mend_3_0_post_verifies():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(status_code=200, text="{}")
        core._post_v3("https://api-saas.mend.io/api/v3.0/x", "tok", {}, {})
    assert post.call_args.kwargs["verify"] is True


def test_the_azure_call_verifies():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=200, text="{}")
        core.call_azure_api(api_type="GET", api="wit/workitems/1", data={}, project="TestProj")
    assert req.call_args.kwargs["verify"] is True


def test_setting_it_false_restores_the_unverified_behaviour():
    with mock.patch.object(core, "conf", _conf(ssl_verify=False)), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    assert get.call_args.kwargs["verify"] is False


def test_a_ca_bundle_path_reaches_requests_verbatim():
    with mock.patch.object(core, "conf", _conf(ssl_verify="/etc/ssl/corp-ca.pem")), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    assert get.call_args.kwargs["verify"] == "/etc/ssl/corp-ca.pem"


# --------------------------------------------------------------- a verification failure is loud

def test_a_certificate_failure_is_reported_as_such_not_as_a_generic_error(caplog):
    """The one way this change can break a run. The error has to name the fix, or an operator is
    left reading a stack trace about SSL."""
    import requests as real_requests
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get",
                           side_effect=real_requests.exceptions.SSLError("bad handshake")):
        with caplog.at_level("ERROR"):
            payload, code = core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    assert code == 2
    assert "MEND_SSLVERIFY" in caplog.text


def test_a_certificate_failure_does_not_silently_retry_unverified():
    """An automatic downgrade to unverified is exactly what an attacker would trigger."""
    import requests as real_requests
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get",
                           side_effect=real_requests.exceptions.SSLError("bad handshake")) as get:
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    assert all(call.kwargs.get("verify") is True for call in get.call_args_list)


# ------------------------------------------------- with verification off, nothing leaks to stderr

def test_turning_verification_off_suppresses_urllibs_own_warning():
    """The warning the pipeline showed as a raw connectionpool.py:1099 line came from the 2.0
    login, the one transport with no catch_warnings block. Suppressing at source covers every
    call site instead of three out of four."""
    with mock.patch.object(core, "conf", _conf(ssl_verify="false")), \
         mock.patch.object(core, "TLS_WARNINGS_SILENCED", False), \
         mock.patch.object(core.urllib3, "disable_warnings") as disable:
        assert core.verify_setting() is False
    disable.assert_called_once()


def test_the_suppression_happens_only_once():
    with mock.patch.object(core, "conf", _conf(ssl_verify="false")), \
         mock.patch.object(core, "TLS_WARNINGS_SILENCED", False), \
         mock.patch.object(core.urllib3, "disable_warnings") as disable:
        for _ in range(5):
            core.verify_setting()
    disable.assert_called_once()


def test_verifying_normally_never_suppresses_anything():
    """If a warning ever does appear while verification is on, it means something real and must
    not be hidden."""
    with mock.patch.object(core, "conf", _conf(ssl_verify="true")), \
         mock.patch.object(core, "TLS_WARNINGS_SILENCED", False), \
         mock.patch.object(core.urllib3, "disable_warnings") as disable:
        assert core.verify_setting() is True
    disable.assert_not_called()
