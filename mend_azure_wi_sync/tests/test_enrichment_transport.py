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


def test_a_persistent_403_disables_enrichment_for_the_rest_of_the_run(caplog):
    """IMPORTANT 2: an org with 2.0 access but no 3.0 entitlement 403s on every 3.0 call.
    Without this, ~400 projects each cost a doomed login + retry, and the shared 2.0 JWT
    cache routing depends on gets repeatedly invalidated by call_ws_api_v3's own retry."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2", return_value=({"message": "denied"}, 403)):
        with caplog.at_level("WARNING"):
            core.call_ws_api_v3("a")
    assert core.enrichment_disabled is True
    assert len([r for r in caplog.records if "disabling enrichment" in r.message]) == 1


def test_the_disable_warning_logs_only_once_across_repeated_403s(caplog):
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2", return_value=({"message": "denied"}, 403)):
        with caplog.at_level("WARNING"):
            core.call_ws_api_v3("a")
            core.call_ws_api_v3("b")
    assert len([r for r in caplog.records if "disabling enrichment" in r.message]) == 1


def test_a_success_does_not_disable_enrichment():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_post_v2_login", return_value=(SESSION, 0)), \
         mock.patch.object(core, "_get_v2", return_value=({"response": []}, 0)):
        core.call_ws_api_v3("a")
    assert core.enrichment_disabled is False
