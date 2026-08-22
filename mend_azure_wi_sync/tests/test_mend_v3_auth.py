from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(email="a@b.com", api_url="api-saas.mend.io", ws_user_key="uk-1",
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


def test_login_posts_to_the_api_host_not_the_sca_host():
    """_post_v2_login is the one request that carries userKey/orgToken. It must never be sent
    to conf.ws_url (the 1.4 SCA app host) -- only to conf.api_url."""
    _reset()
    conf = mock.MagicMock(email="a@b.com", api_url="api-saas.mend.io",
                          ws_url="saas.mend.io", ws_user_key="uk-1",
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


def test_a_persistent_failure_reports_errorcode_2():
    """Callers check for 2; a raw HTTP status leaking through would read as success."""
    _reset()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"message": "nope"}, 500)):
        payload, errorcode = core.call_ws_api_v3("orgs/o-1/projects")
    assert errorcode == 2
