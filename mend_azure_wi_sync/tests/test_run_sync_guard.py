from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.core import sync_had_fatal_error, global_errors as frozen_counter

PROJECTS = [{"uuid": "p-1", "name": "api", "application_uuid": "a-1",
             "application_name": "ProductX", "last_scanned": "", "tags": {}}]


def _conf(**kw):
    base = dict(routing="false", wsproducttoken="", wsprojecttoken="", wsexcludetoken="",
                severity="high", azure_project="Book", reponame="", azure_area="",
                reachability="false")
    base.update(kw)
    return mock.MagicMock(**base)


def test_run_sync_aborts_when_existing_items_cannot_be_read():
    """A failed WIQL query must never be treated as 'this project has no work items yet'.
    Now doubly so: with closure live, an empty read also looks like 'everything is remediated'."""
    with mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=None), \
         mock.patch.object(core, "sync_project_v3") as sync, \
         mock.patch.object(core, "conf", _conf()):
        before = core.global_errors
        result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    sync.assert_not_called()
    assert core.global_errors == before + 1
    assert "aborted" in result.lower()


def test_run_sync_aborts_when_the_mend_project_list_is_incomplete():
    """A partial project list makes a project we failed to read look exactly like one whose
    findings are all gone -- and reconciliation would close its work items."""
    with mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, False)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]) as exist, \
         mock.patch.object(core, "sync_project_v3") as sync, \
         mock.patch.object(core, "conf", _conf()):
        result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    sync.assert_not_called()
    exist.assert_not_called()
    assert core.sync_had_fatal_error() is True
    assert "aborted" in result.lower()


def test_a_failed_run_is_reported_as_fatal():
    with mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=None), \
         mock.patch.object(core, "sync_project_v3"), \
         mock.patch.object(core, "conf", _conf()):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    assert core.sync_had_fatal_error() is True


def test_a_clean_run_is_not_reported_as_fatal():
    """Guards the reset: run_sync must clear the flag on entry, or a failure in an
    earlier run (or an earlier test) leaks forward."""
    core.run_failed = True
    with mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True), \
         mock.patch.object(core, "conf", _conf()):
        core.global_errors = 0
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    assert core.sync_had_fatal_error() is False
    # Ported from the retired 1.4 sync-state wiring (test_a_successful_verdict_adds_no_errors):
    # a healthy run must not manufacture errors of its own.
    assert core.error_count() == 0


def test_one_projects_failure_does_not_fail_the_whole_run(caplog):
    """Ported from the retired 1.4 sync-state wiring: a per-project failure is logged and
    counted, never fatal, and the remaining projects are still synced."""
    projects = PROJECTS + [{"uuid": "p-2", "name": "web", "application_uuid": "a-1",
                            "application_name": "ProductX", "last_scanned": "", "tags": {}}]
    seen = []

    def _explode_once(uuid, floor):
        seen.append(uuid)
        if uuid == "p-1":
            raise RuntimeError("Mend said no")
        return ({}, True)

    core.global_errors = 0
    with mock.patch.object(core, "fetch_v3_projects", return_value=(projects, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "fetch_v3_desired", side_effect=_explode_once), \
         mock.patch.object(core, "create_wi_v3", return_value=(0, 0, 0)), \
         mock.patch.object(core, "reconcile_project", return_value=(0, 0, 0, 0, 0)), \
         mock.patch.object(core, "conf", _conf()), \
         caplog.at_level("ERROR"):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    assert seen == ["p-1", "p-2"]
    assert core.error_count() == 1
    assert core.sync_had_fatal_error() is False
    assert any("ProductX/api" in r.getMessage() for r in caplog.records)


def test_a_function_reads_live_state_but_an_imported_value_is_frozen():
    """This is why sync_had_fatal_error is a function and not a flag: azure_wi_sync.py
    imports names at module load, so an imported boolean would be frozen at False forever —
    the trap global_errors already falls into."""
    core.run_failed = True
    core.global_errors = 5
    assert sync_had_fatal_error() is True      # function -> live
    assert frozen_counter == 0                 # value    -> frozen at import time
