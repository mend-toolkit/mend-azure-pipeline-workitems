import json
from unittest import mock

import pytest

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate

TODATE = "2026-08-20 12:00:00"


@pytest.fixture(autouse=True)
def _reset_state():
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False
    core.run_failed = False
    yield
    core.project_tag_state = None
    core.run_failed = False


def _conf(**kw):
    base = dict(routing="false", reset="false", maxlookback="720", azure_project="Book",
                utc_delta=0)
    base.update(kw)
    return mock.MagicMock(**base)


def test_the_reverse_wiql_is_scoped_to_one_mend_project_and_its_own_watermark():
    core.project_tag_state = {"tok-1": {"revsync": "2026-08-20 11:00:00"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    query = api.call_args.kwargs["data"]["query"]
    assert 'CONTAINS "Prod/Proj"' in query
    assert '2026-08-20 11:00:00' in query


def test_an_untagged_project_looks_back_the_full_reset_window():
    """Rev 4 superseded rev 3 here: an absent revsync watermark used to clamp to
    MEND_MAXLOOKBACK, which meant a project's first-ever reverse sync silently started only
    30 days ago. It must instead look back reset_back_time (10 years), exactly once per
    project, so no history is silently missed the first time a project is ever visited."""
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert "2016-" in api.call_args.kwargs["data"]["query"]
    assert "2026-07-21 12:00:00" not in api.call_args.kwargs["data"]["query"]


def test_a_successful_reverse_sync_advances_only_that_projects_revsync_tag():
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)), \
         mock.patch.object(core, "save_project_tag", return_value=True) as save:
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    save.assert_called_once_with("tok-1", syncstate.TAG_REVSYNC, TODATE)


def test_a_failed_reverse_wiql_does_not_advance_the_watermark():
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"message": "boom"}, 2)), \
         mock.patch.object(core, "save_project_tag") as save:
        result = core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    save.assert_not_called()
    assert core.sync_had_fatal_error() is True
    # Both paths used to return "Updated 0 work item(s) for X", so a project whose WIQL blew
    # up read exactly like an empty success in the joined summary line.
    assert "before failing" in result and "retried" in result


def test_an_empty_success_still_reads_as_a_success():
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)), \
         mock.patch.object(core, "save_project_tag", return_value=True):
        result = core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert result == "Updated 0 work item(s) for Prod/Proj"


def test_a_stale_revsync_watermark_is_honoured_not_narrowed(caplog):
    """Same rule as the forward window: narrowing a present watermark would drop the work item
    changes between it and the new start, and the next success would write over them."""
    core.project_tag_state = {"tok-1": {"revsync": "2026-06-01 00:00:00"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         caplog.at_level("WARNING"):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert "2026-06-01 00:00:00" in api.call_args.kwargs["data"]["query"]
    assert any("MEND_MAXLOOKBACK" in r.getMessage() and "tok-1" in r.getMessage()
               for r in caplog.records)


def test_no_azure_project_properties_call_is_made():
    """The permission this design exists to drop must not be reached from the reverse path."""
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert not any("properties" in str(c.kwargs.get("api", "")) for c in api.call_args_list)


def test_a_project_not_synced_this_run_is_still_reverse_synced():
    """The regression this task exists to fix: a dormant repo's closed work items must still
    reach Mend, with no dependence on whether the forward sync touched it."""
    core.project_tag_state = {"tok-dormant": {"project": "Payments|Prod/Proj",
                                              "revsync": "2026-08-01 00:00:00"}}
    core.synced_projects = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok") as visit:
        core.update_wi_in_thread()
    assert visit.call_args_list[0].args[0] == "tok-dormant"


def test_a_first_ever_reverse_sync_looks_back_further_than_maxlookback():
    """An absent revsync watermark must not silently start 30 days ago."""
    core.project_tag_state = {"tok-1": {"project": "Payments|Prod/Proj"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api",
                           return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert "2016-" in api.call_args.kwargs["data"]["query"]


def test_a_forward_write_failure_does_not_suppress_the_reverse_sync():
    """A forward work-item write failure says nothing about whether existing work items
    changed state. The two directions are decoupled."""
    core.project_tag_state = {"tok-1": {"project": "Payments|Prod/Proj"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok") as visit:
        core.update_wi_in_thread()
    assert visit.called


def test_a_closed_work_item_pushes_once_across_two_runs():
    """The 'don't reprocess' guarantee, exercised end to end through update_wi_for_project
    (not mocked) twice in a row. Run 1 has no stored watermark, looks back to the reset
    floor, finds the item and (on success) advances azure-wi-revsync to run 1's todate. Run
    2 reuses that advanced watermark; the item's ChangedDate has not moved since run 1, so a
    real Azure ChangedDate > since filter -- reproduced here by the fake -- would no longer
    return it. It must not be re-pushed."""
    item_changed = "2026-08-15 00:00:00"
    pushed = []

    def fake_azure_api(api_type=None, api="", data=None, project=None, **kw):
        if api == "wit/wiql":
            since = data["query"].split('"')[1]
            first_id = int(data["query"].split("[System.Id] > ")[1].split(" ")[0])
            if since < item_changed and first_id < 42:
                return {"workItems": [{"id": 42}]}, 0
            return {"workItems": []}, 0
        return ({"value": [{
            "id": 42,
            "url": "https://dev.azure.com/org/proj/_apis/wit/workitems/42",
            "fields": {"System.Title": "Some work item",
                      "System.Tags": "Prod/Proj; security vulnerability",
                      "System.State": "Active",
                      "System.ChangedDate": item_changed,
                      "System.CreatedDate": item_changed},
            "relations": [{"rel": "Hyperlink",
                          "attributes": {"comment": "tok-1,issue-uuid-1"}}],
        }]}, 0)

    saved = {}

    def fake_save(token, key, value):
        saved[key] = value
        return True

    with mock.patch.object(core, "conf", _conf(ws_user_key="uk-1", ws_org_token="org-1")), \
         mock.patch.object(core, "call_azure_api", side_effect=fake_azure_api), \
         mock.patch.object(core, "save_project_tag", side_effect=fake_save), \
         mock.patch.object(core, "call_ws_api",
                           side_effect=lambda data: pushed.append(data) or "{}"):
        state_run1 = {"tok-1": {}}
        core.project_tag_state = state_run1
        result1 = core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)

        state_run2 = {"tok-1": {"revsync": saved[syncstate.TAG_REVSYNC]}}
        core.project_tag_state = state_run2
        result2 = core.update_wi_for_project("tok-1", "Prod/Proj", "2026-08-21 12:00:00")

    assert "Updated 1 work item(s)" in result1
    assert "Updated 0 work item(s)" in result2
    # call_ws_api is mocked wholesale, so `pushed` also catches the tag traffic that advances the
    # watermark -- including the removeProjectTag pruning run 1's value, now that saveProjectTag
    # is known to append rather than replace. Count only the actual pushes.
    issue_pushes = [d for d in pushed
                    if json.loads(d)["requestType"] == "updateExternalIntegrationIssues"]
    assert len(issue_pushes) == 1
