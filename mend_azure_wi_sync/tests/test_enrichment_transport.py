from unittest import mock

import pytest

from mend_azure_wi_sync import core

SESSION = {"retVal": {"jwtToken": "jwt-abc"}}


@pytest.fixture(autouse=True)
def _clear_token_cache():
    core.mend_v2_session = None
    yield
    core.mend_v2_session = None


def _conf():
    return mock.MagicMock(email="svc@example.com", ws_user_key="uk", ws_org_token="ot",
                          api_url="https://api-saas.mend.io", proxy={})


def test_v3_url_is_built_from_api_url_not_ws_url():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2", return_value=({"response": []}, 0)) as get:
        core.call_ws_api_v3("projects/abc/dependencies/findings/security", {"limit": "10"})
    url = get.call_args[0][0]
    assert url == "https://api-saas.mend.io/api/v3.0/projects/abc/dependencies/findings/security"
    assert get.call_args[0][1] == "jwt-abc"


def test_v3_reuses_the_cached_2_0_token_without_logging_in_again():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)) as login, \
         mock.patch.object(core, "_get_v2", return_value=({"response": []}, 0)):
        core.call_ws_api_v3("a")
        core.call_ws_api_v3("b")
    assert login.call_count == 1


def test_a_403_triggers_exactly_one_re_login_and_retry():
    responses = [({"message": "denied"}, 403), ({"response": ["ok"]}, 0)]
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)) as login, \
         mock.patch.object(core, "_get_v2", side_effect=responses) as get:
        payload, errorcode = core.call_ws_api_v3("a")
    assert (payload, errorcode) == ({"response": ["ok"]}, 0)
    assert get.call_count == 2
    assert login.call_count == 2      # cache cleared, then re-minted


def test_a_persistent_failure_collapses_to_errorcode_2():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2", return_value=({"message": "nope"}, 500)):
        payload, errorcode = core.call_ws_api_v3("a")
    assert errorcode == 2
