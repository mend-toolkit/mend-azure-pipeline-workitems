import json
from unittest import mock

import pytest

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate


import contextlib
import logging


@contextlib.contextmanager
def caplog_at_error():
    """Collect ERROR records without a caplog fixture, for use inside `with` chains."""
    records = []

    class _Sink(logging.Handler):
        def emit(self, record):
            records.append(record)

    sink = _Sink(level=logging.ERROR)
    core.logger.addHandler(sink)
    try:
        yield records
    finally:
        core.logger.removeHandler(sink)


@pytest.fixture(autouse=True)
def _reset_state():
    core.project_tag_state = None
    core.project_tag_values = {}
    core.project_raw_tags = {}
    core.tag_state_available = True
    core.tag_sweep_ok = True
    core.TAG_WARNED = False
    yield
    core.project_tag_state = None
    core.project_tag_values = {}
    core.project_raw_tags = {}
    core.tag_state_available = True
    core.tag_sweep_ok = True
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


def test_removing_a_tag_sends_the_stored_value_when_it_has_one():
    """removeProjectTag matches on the tagValue and deletes only that value (verified live
    2026-08-21), so the caller must pass what the org sweep read back -- "" names nothing."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        core.remove_project_tag("tok-1", syncstate.TAG_FAILED, "2026-08-19 11:00:00")
    assert json.loads(api.call_args.kwargs["data"])["tagValue"] == "2026-08-19 11:00:00"


def test_rows_that_parse_to_nothing_are_reported_not_treated_as_no_state(caplog):
    """A response shaped differently from {"token":…, "tags":{…}} left tag_state_available True,
    so the run logged "Sync state: Mend project tags" while every window silently fell to the
    clamp, nothing was ever retried, and migration_seed re-read the frozen legacy property
    forever. No speculative key-name fallbacks: the point is to make a mismatch loud."""
    unexpected = json.dumps({"projectTags": [{"projectToken": "tok-1",
                                             "tags": [{"key": "azure-wi-lastrun"}]}]})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=unexpected), \
         caplog.at_level("ERROR"):
        assert core.fetch_project_tag_state() == {}
    assert core.tag_state_available is False
    assert any("unexpected shape" in r.getMessage() for r in caplog.records)


def test_an_empty_org_with_no_tags_yet_is_not_reported_as_a_shape_problem(caplog):
    """The first run after upgrade legitimately has no tagged project. That must stay quiet, or
    the once-per-run warning budget is spent before any real failure can use it."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=json.dumps({"projectTags": []})), \
         caplog.at_level("ERROR"):
        assert core.fetch_project_tag_state() == {}
    assert core.tag_state_available is True
    assert caplog.records == []


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
                           side_effect=lambda t, k, v="": calls.append(("remove", k)) or True):
        core.apply_tag_ops("tok-1", syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00",
                                                     "2026-08-19 11:00:00"))
    assert calls == [("save", syncstate.TAG_LASTRUN), ("remove", syncstate.TAG_FAILED)]


def test_apply_tag_ops_skips_the_clear_when_the_advance_failed():
    """Clearing the retry flag after a failed advance would drop the project from the retry
    queue while its watermark still points at the unread window."""
    calls = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "save_project_tag", return_value=False), \
         mock.patch.object(core, "remove_project_tag",
                           side_effect=lambda t, k, v="": calls.append(k) or True):
        core.apply_tag_ops("tok-1", syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00",
                                                     "2026-08-19 11:00:00"))
    assert calls == []


LIVE_SHAPE = json.dumps({"projectTags": [
    # Verbatim from the live org (2026-08-21): tags is a dict of LISTS, most projects carry
    # only CLI scan tags, and the two routed ones carry ours alongside the routing tags.
    {"name": "AZ_IaC", "token": "tok-scan-only",
     "tags": {"CTX": ["99ef77b0"], "commitId": ["fe39bbda"],
              "repoFullName": ["DotNET-Demo/IaC@master"]}},
    {"name": "Test", "token": "tok-untagged", "tags": {}},
    {"name": "Test Workitems_master", "token": "tok-routed",
     "tags": {"azure-wi-project": ["Test Pipeline Workitems|Test Pipeline Workitems/Test Workitems_master"],
              "azure-branch": ["refs/heads/master"],
              "azure-project": ["Test Pipeline Workitems"],
              "azure-repo": ["Test Workitems"],
              "azure-wi-lastrun": ["2026-08-21 14:36:34"]}}]})


def test_the_live_1_4_row_shape_is_read_without_a_shape_warning(caplog):
    """The sweep returns list-valued tags. Reading them as strings parsed the whole org to {},
    so every window fell back to MEND_MAXLOOKBACK while the tag WRITES were succeeding -- which
    is why the warning's advice about MEND_USERKEY permissions pointed the wrong way."""
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=LIVE_SHAPE), \
         caplog.at_level("ERROR"):
        state = core.fetch_project_tag_state()
    assert state == {"tok-routed": {"lastrun": "2026-08-21 14:36:34"}}
    assert core.tag_state_available is True
    assert caplog.records == []


def test_an_org_whose_projects_carry_only_scan_tags_is_not_a_shape_problem(caplog):
    """The first run after upgrade: rows are non-empty and readable, but no project carries an
    azure-wi-* tag yet. Empty state here is the truth, not a mismatch."""
    rows_only_scan_tags = json.dumps({"projectTags": [
        {"name": "AZ_IaC", "token": "tok-1", "tags": {"CTX": ["abc"], "commitId": ["def"]}},
        {"name": "Test", "token": "tok-2", "tags": {}}]})
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=rows_only_scan_tags), \
         caplog.at_level("ERROR"):
        assert core.fetch_project_tag_state() == {}
    assert core.tag_state_available is True
    assert caplog.records == []


# --- saveProjectTag creates a second tag under the same key, it does not replace ---
# Verified live 2026-08-21, from Mend's own UI as well as the API: two runs left
# azure-wi-lastrun carrying both "2026-08-21 14:36:34" and "2026-08-21 14:55:01". The
# superseded value must be deleted explicitly, or every key grows by one value per run and
# runs into the (still unverified) tag value limit.

def _tag_calls(api):
    """[(requestType, tagKey, tagValue)] in call order."""
    out = []
    for call in api.call_args_list:
        body = json.loads(call.kwargs["data"])
        if body.get("requestType") in ("saveProjectTag", "removeProjectTag"):
            out.append((body["requestType"], body["tagKey"], body["tagValue"]))
    return out


def _reset_tag_globals(values=None):
    """Seed the value map the sweep would have produced. The autouse fixture clears it after."""
    core.project_tag_values = values if values is not None else {}


def test_saving_a_watermark_deletes_the_value_it_supersedes():
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-21 14:36:34"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        assert core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01") is True
    assert _tag_calls(api) == [
        ("saveProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01"),
        ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:36:34")]


def test_the_new_value_is_saved_before_anything_is_deleted():
    """Order is the safety property. Save-then-prune leaves both values if the prune fails, and
    latest-wins reads that correctly. Prune-then-save would leave the project with NO watermark
    if the save then failed, silently widening its next window to MEND_MAXLOOKBACK."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-20 10:00:00", "2026-08-21 14:36:34"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
    calls = _tag_calls(api)
    assert calls[0] == ("saveProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
    assert sorted(calls[1:]) == sorted([
        ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-20 10:00:00"),
        ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:36:34")])


def test_nothing_is_deleted_when_the_save_failed():
    """A failed save must not take the previous watermark with it -- that is the one value still
    describing what was actually read."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-21 14:36:34"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5001}') as api:
        assert core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01") is False
    assert [c for c in _tag_calls(api) if c[0] == "removeProjectTag"] == []


def test_the_value_just_written_is_never_deleted():
    """Re-saving the value already stored must be a no-op prune, not a delete of itself."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-21 14:55:01"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
    assert [c for c in _tag_calls(api) if c[0] == "removeProjectTag"] == []


def test_a_second_save_in_the_same_run_prunes_only_the_first_runs_value():
    """The in-memory value map has to track what this run wrote, or the second save re-issues a
    remove for a value already gone and, worse, misses the one it just superseded."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-21 14:36:34"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
        core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 15:10:00")
    assert _tag_calls(api) == [
        ("saveProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01"),
        ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:36:34"),
        ("saveProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 15:10:00"),
        ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")]


def test_the_verdict_path_prunes_the_previous_watermark_and_every_failed_value():
    """tag_ops names one TAG_FAILED value (the winner). With append semantics a project that
    failed several runs carries several, and clearing the retry queue means clearing them all --
    one left behind keeps the project in the queue forever."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-20 10:00:00"],
                                  "failed": ["2026-08-19 09:00:00", "2026-08-20 09:00:00"]}})
    state = {"tok-1": {"lastrun": "2026-08-20 10:00:00", "failed": "2026-08-20 09:00:00"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"projectTags": {}}') as api:
        core.record_verdict("tok-1", syncstate.VERDICT_OK, "2026-08-21 14:55:01", state)
    calls = _tag_calls(api)
    assert calls[0] == ("saveProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
    assert ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-20 10:00:00") in calls
    assert ("removeProjectTag", syncstate.TAG_FAILED, "2026-08-19 09:00:00") in calls
    assert ("removeProjectTag", syncstate.TAG_FAILED, "2026-08-20 09:00:00") in calls


# --- what counts as a successful write ---
# Verified live 2026-08-21: a saveProjectTag whose value demonstrably landed in Mend
# (azure-wi-lastrun = the run's todate, confirmed in the org's tags afterwards) was reported as
# a failure, because _tag_call demanded a "projectTags" key in the response. Requiring a key
# nothing documents made every successful write look failed. Mend 1.4 signals failure the way
# get_prj_list_modified already reads it: errorCode / errorMessage in the body.

def test_a_success_response_without_a_projecttags_key_is_not_a_failure():
    _reset_tag_globals()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value="{}"):
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01") is True
    assert core.tag_state_available is True


def test_an_error_body_is_a_failure():
    _reset_tag_globals()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"errorCode": 5001, "errorMessage": "user is not allowed"}'), \
         caplog_at_error() as records:
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "x") is False
    assert core.tag_state_available is False
    assert any("user is not allowed" in r.getMessage() for r in records)


def test_a_zero_errorcode_is_success_not_failure():
    """Some 1.4 responses carry errorCode: 0 on success. Only a truthy code, or any
    errorMessage, means the write was rejected."""
    _reset_tag_globals()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 0}'):
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "x") is True
    assert core.tag_state_available is True


def test_an_empty_body_is_still_a_failure():
    """call_ws_api returns "" for any non-200 and the status code is gone by the time it gets
    here, so an empty body cannot be told apart from a rejected write. Report it."""
    _reset_tag_globals()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=""):
        assert core.save_project_tag("tok-1", syncstate.TAG_LASTRUN, "x") is False
    assert core.tag_state_available is False


def test_a_successful_save_still_prunes_when_the_body_has_no_projecttags_key():
    """The two fixes have to compose: the prune only runs on a save reported successful."""
    _reset_tag_globals({"tok-1": {"lastrun": ["2026-08-21 14:36:34"]}})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value="{}") as api:
        core.replace_project_tag("tok-1", syncstate.TAG_LASTRUN, "2026-08-21 14:55:01")
    assert ("removeProjectTag", syncstate.TAG_LASTRUN, "2026-08-21 14:36:34") in _tag_calls(api)
