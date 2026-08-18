from unittest import mock

import pytest

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs


SESSION = {"retVal": {"jwtToken": "jwt-abc", "refreshToken": "ref-xyz",
                      "orgUuid": "org-1", "email": "svc@example.com"}}


@pytest.fixture(autouse=True)
def _clear_token_cache():
    core.mend_v2_session = None
    yield
    core.mend_v2_session = None


def test_email_reads_both_aliases():
    import os
    with mock.patch.dict(os.environ, {"MEND_EMAIL": "svc@example.com"}, clear=True):
        assert varenvs.get_env("wsemail") == "svc@example.com"
    with mock.patch.dict(os.environ, {"WS_EMAIL": "svc@example.com"}, clear=True):
        assert varenvs.get_env("wsemail") == "svc@example.com"


def test_check_patterns_requires_email_only_under_routing():
    # A real Config, not a MagicMock: check_patterns re.match()es conf.ws_user_key on its
    # first line (core.py:69). See test_routing_config.py::_valid_conf.
    from mend_azure_wi_sync.tests.test_routing_config import _valid_conf
    with mock.patch.object(core, "conf", _valid_conf(routing="true", email="")):
        assert any("EMAIL" in el for el in core.check_patterns())
    with mock.patch.object(core, "conf", _valid_conf(routing="false", email="")):
        assert not any("EMAIL" in el for el in core.check_patterns())


def test_token_is_acquired_once_and_cached():
    with mock.patch.object(core, "conf", mock.MagicMock(email="svc@example.com",
                                                        ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)) as login:
        assert core.mend_v2_token() == "jwt-abc"
        assert core.mend_v2_token() == "jwt-abc"
    assert login.call_count == 1


def test_login_failure_returns_empty_and_does_not_cache():
    with mock.patch.object(core, "conf", mock.MagicMock(email="svc@example.com",
                                                        ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "_post_v2_login",
                           return_value=({"message": "bad creds"}, 2)) as login:
        assert core.mend_v2_token() == ""
        assert core.mend_v2_token() == ""
    assert login.call_count == 2      # a failure must not be cached as success


def test_a_401_triggers_exactly_one_re_login_and_retry():
    """The JWT lives 10 minutes. One retry covers expiry mid-run; a loop would not."""
    responses = [({"message": "unauthorized"}, 401), ({"retVal": ["ok"]}, 0)]
    with mock.patch.object(core, "conf", mock.MagicMock(email="svc@example.com",
                                                        ws_user_key="uk", ws_org_token="ot",
                                                        ws_url="https://x", api_url="https://api-x",
                                                        proxy={})), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)) as login, \
         mock.patch.object(core, "_get_v2", side_effect=responses) as get:
        payload, err = core.call_ws_api_v2("orgs/ot/entities")
    assert err == 0
    assert get.call_count == 2
    assert login.call_count == 2      # initial + one re-login


def test_a_persistent_401_gives_up_rather_than_looping():
    with mock.patch.object(core, "conf", mock.MagicMock(email="svc@example.com",
                                                        ws_user_key="uk", ws_org_token="ot",
                                                        ws_url="https://x", api_url="https://api-x",
                                                        proxy={})), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2",
                           return_value=({"message": "unauthorized"}, 401)) as get:
        payload, err = core.call_ws_api_v2("orgs/ot/entities")
    assert err != 0
    assert get.call_count == 2


def test_the_token_never_reaches_conf_json():
    """conf_json values are substitutable into work item descriptions via MEND_CUSTOMFIELDS,
    so a cached JWT reachable from there would be written into Azure DevOps in plain text.

    Mint a token first — asserting on a Config that never saw one proves nothing.
    """
    from mend_azure_wi_sync.tests.test_routing_config import _valid_conf
    conf = _valid_conf(routing="true", email="svc@example.com")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)):
        assert core.mend_v2_token() == "jwt-abc"

    blob = str(conf.conf_json())
    assert "jwt-abc" not in blob
    assert "svc@example.com" not in blob
    assert "email" not in conf.conf_json()
    assert "wsapiurl" not in conf.conf_json()
