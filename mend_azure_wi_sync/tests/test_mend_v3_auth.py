from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(email="a@b.com", ws_url="saas.mend.io", ws_user_key="uk-1",
                          ws_org_token="tok-abc", org_uuid="", proxy={})


def _reset():
    core.mend_v2_session = None


def test_login_success_returns_the_jwt():
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login",
                           return_value=({"retVal": {"jwtToken": "jwt-1"}}, 0)):
        assert core.mend_v2_token() == "jwt-1"


def test_the_token_is_cached_so_login_happens_once():
    _reset()
    login = mock.Mock(return_value=({"retVal": {"jwtToken": "jwt-1"}}, 0))
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", login):
        core.mend_v2_token()
        core.mend_v2_token()
    assert login.call_count == 1


def test_a_failed_login_returns_empty_and_is_not_cached():
    """A cached failure would poison every later call in the run."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=({"error": "bad"}, 2)):
        assert core.mend_v2_token() == ""
    assert core.mend_v2_session is None


def test_mend_api_url_derives_from_ws_url():
    conf = mock.MagicMock(ws_url="https://saas.mend.io")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == "https://api-saas.mend.io"


def test_mend_api_url_derives_from_a_bare_host():
    conf = mock.MagicMock(ws_url="saas.mend.io")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == "https://api-saas.mend.io"


def test_mend_api_url_derives_from_a_trailing_slash():
    conf = mock.MagicMock(ws_url="https://saas.mend.io/")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == "https://api-saas.mend.io"


def test_mend_api_url_derives_from_a_url_carrying_a_path():
    conf = mock.MagicMock(ws_url="saas.mend.io/wss/agent")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == "https://api-saas.mend.io"


def test_mend_api_url_is_not_double_prefixed():
    conf = mock.MagicMock(ws_url="https://api-saas.mend.io")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == "https://api-saas.mend.io"


def test_mend_api_url_empty_ws_url_yields_empty_string():
    conf = mock.MagicMock(ws_url="")
    with mock.patch.object(core, "conf", conf):
        assert core.mend_api_url() == ""


def test_v3_call_builds_the_url_from_the_api_host_not_the_sca_host():
    """2.0/3.0 live on the API host; deriving from MEND_URL would hit the wrong server."""
    _reset()
    seen = {}

    def fake_get(url, token, params):
        seen["url"] = url
        return {"response": []}, 0

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", fake_get):
        core.call_ws_api_v3("orgs/o-1/projects")
    assert seen["url"] == "https://api-saas.mend.io/api/v3.0/orgs/o-1/projects"


def test_a_401_re_mints_the_token_once_and_retries():
    _reset()
    calls = []

    def fake_get(url, token, params):
        calls.append(token)
        return ({}, 401) if len(calls) == 1 else ({"response": []}, 0)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login",
                           return_value=({"retVal": {"jwtToken": "jwt-2"}}, 0)), \
         mock.patch.object(core, "_get_v2", fake_get):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects")
    assert errorcode == 0
    assert len(calls) == 2


def test_login_targets_the_derived_host_not_the_sca_host():
    """_post_v2_login is the one request that carries userKey/orgToken. It must target the
    host derived from MEND_URL (mend_api_url()), never conf.ws_url (the 1.4 SCA app host)
    itself."""
    _reset()
    conf = mock.MagicMock(email="a@b.com",
                          ws_url="https://saas.mend.io", ws_user_key="uk-1",
                          ws_org_token="tok-abc", proxy={})
    seen = {}

    class FakeResponse:
        status_code = 200
        text = '{"retVal": {"jwtToken": "jwt-1"}}'

    def fake_post(url, **kwargs):
        seen["url"] = url
        return FakeResponse()

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core.requests, "post", fake_post):
        core._post_v2_login()
    assert seen["url"] == "https://api-saas.mend.io/api/v2.0/login"


def test_v3_call_with_method_post_goes_through_post_not_get():
    """/projects/summaries is POST-only in the 3.0 spec; a GET-only transport would 404/405."""
    _reset()
    seen = {}

    def fake_post(url, token, body, params):
        seen["url"] = url
        seen["body"] = body
        seen["params"] = params
        return {"response": []}, 0

    def fail_get(*a, **k):
        raise AssertionError("GET must not be used for a POST-only endpoint")

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_post_v3", fake_post), \
         mock.patch.object(core, "_get_v2", fail_get):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects/summaries",
                                                 params={"limit": 1000}, method="POST")
    assert errorcode == 0
    assert seen["url"] == "https://api-saas.mend.io/api/v3.0/orgs/o-1/projects/summaries"
    assert seen["params"] == {"limit": 1000}


def test_v3_call_defaults_to_get_so_existing_callers_are_unchanged():
    _reset()

    def fail_post(*a, **k):
        raise AssertionError("GET callers must not be routed through POST")

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"response": []}, 0)), \
         mock.patch.object(core, "_post_v3", fail_post):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects")
    assert errorcode == 0


def test_a_401_on_a_post_call_re_mints_the_token_once_and_retries():
    _reset()
    calls = []

    def fake_post(url, token, body, params):
        calls.append(token)
        return ({}, 401) if len(calls) == 1 else ({"response": []}, 0)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login",
                           return_value=({"retVal": {"jwtToken": "jwt-2"}}, 0)), \
         mock.patch.object(core, "_post_v3", fake_post):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects/summaries", method="POST")
    assert errorcode == 0
    assert len(calls) == 2


def test_a_persistent_failure_reports_errorcode_2():
    """Callers check for 2; a raw HTTP status leaking through would read as success."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"message": "nope"}, 500)):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects")
    assert errorcode == 2
