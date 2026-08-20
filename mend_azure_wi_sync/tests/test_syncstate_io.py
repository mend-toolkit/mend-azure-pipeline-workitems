import json
from unittest import mock

import pytest

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate


@pytest.fixture(autouse=True)
def _reset_state():
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False
    yield
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False


def _conf():
    return mock.MagicMock(ws_user_key="uk", ws_org_token="ot")


ONE_PROJECT = json.dumps({"projectTags": [
    {"name": "p", "token": "tok-1", "tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}}]})


def test_the_org_tag_sweep_happens_once_per_run():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=ONE_PROJECT) as api:
        first = core.fetch_project_tag_state()
        second = core.fetch_project_tag_state()
    assert first == {"tok-1": {"lastrun": "2026-08-20 10:00:00"}}
    assert second == first
    assert api.call_count == 1


def test_an_unreadable_sweep_yields_empty_state_and_marks_it_unavailable():
    """Empty state must not be confused with 'no projects tagged yet' by the caller, which is
    why tag_state_available exists: it drives the once-per-run warning, not the windows."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5000}'):
        assert core.fetch_project_tag_state() == {}
    assert core.tag_state_available is False


def test_saving_a_tag_sends_the_right_request_type_and_fields():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-20 12:00:00") is True
    body = json.loads(api.call_args.kwargs["data"])
    assert body["requestType"] == "saveProjectTag"
    assert body["projectToken"] == "tok-1"
    assert body["tagKey"] == syncstate.TAG_LASTRUN
    assert body["tagValue"] == "2026-08-20 12:00:00"


def test_removing_a_tag_uses_the_remove_request_type():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        assert core.remove_project_tag("tok-1", syncstate.TAG_FAILED) is True
    assert json.loads(api.call_args.kwargs["data"])["requestType"] == "removeProjectTag"


def test_a_failed_write_returns_false_and_warns_only_once(caplog):
    """400 identical errors per run would make the error count meaningless."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5000}'), \
         caplog.at_level("ERROR"):
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "x") is False
        assert core.save_project_tag("tok-2", syncstate.TAG_LASTRUN, "x") is False
    assert len([r for r in caplog.records if "sync state" in r.getMessage().lower()]) == 1


def test_a_write_failure_never_raises_and_never_sets_run_failed():
    core.run_failed = False
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", side_effect=Exception("boom")):
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "x") is False
    assert core.run_failed is False


def test_apply_tag_ops_runs_saves_and_removes_in_order():
    calls = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "save_project_tag",
                           side_effect=lambda t, k, v: calls.append(("save", k)) or True), \
         mock.patch.object(core, "remove_project_tag",
                           side_effect=lambda t, k: calls.append(("remove", k)) or True):
        core.apply_tag_ops("tok-1", syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00"))
    assert calls == [("save", syncstate.TAG_LASTRUN), ("remove", syncstate.TAG_FAILED)]


def test_apply_tag_ops_skips_the_clear_when_the_advance_failed():
    """Clearing the retry flag after a failed advance would drop the project from the retry
    queue while its watermark still points at the unread window."""
    calls = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "save_project_tag", return_value=False), \
         mock.patch.object(core, "remove_project_tag",
                           side_effect=lambda t, k: calls.append(k) or True):
        core.apply_tag_ops("tok-1", syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00"))
    assert calls == []
