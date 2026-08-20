import json
from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(ws_user_key="uk", ws_org_token="ot")


GOOD = json.dumps({
    "product": {"productName": "Prod"},
    "project": {"projectName": "Proj"},
    "issues": [{"policy": {"enabled": True}, "library": {"keyId": 1}, "policyViolations": []}],
})

EMPTY_BUT_REAL = json.dumps({
    "product": {"productName": "Prod"},
    "project": {"projectName": "Proj"},
    "issues": [],
})


def test_a_successful_fetch_returns_names_then_issues():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=GOOD):
        res = core.fetch_prj_policy("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00")
    assert res[0] == "Prod"
    assert res[1] == "Proj"
    assert len(res[2:]) == 1


def test_a_genuinely_empty_window_is_not_a_failure():
    """This is the distinction the whole design rests on: no findings is a real answer."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=EMPTY_BUT_REAL):
        res = core.fetch_prj_policy("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00")
    assert res is not None
    assert res[2:] == []


def test_a_failed_fetch_returns_none_not_a_short_list():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5000}'):
        assert core.fetch_prj_policy("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00") is None


def test_a_transport_exception_returns_none():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", side_effect=Exception("boom")):
        assert core.fetch_prj_policy("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00") is None
