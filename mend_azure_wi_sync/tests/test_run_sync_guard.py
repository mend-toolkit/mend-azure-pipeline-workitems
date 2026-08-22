from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate
from mend_azure_wi_sync.core import sync_had_fatal_error, global_errors as frozen_counter


def _conf():
    return mock.MagicMock(wsproducttoken="", wsprojecttoken="", wsexcludetoken="")


def test_run_sync_aborts_when_existing_items_cannot_be_read():
    """A failed WIQL query must never be treated as 'this project has no work items yet'."""
    with mock.patch.object(core, "get_prj_list_modified", return_value=["prj-token-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=None), \
         mock.patch.object(core, "create_wi") as create_wi, \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "conf", _conf()):
        before = core.global_errors
        result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    create_wi.assert_not_called()
    assert core.global_errors == before + 1
    assert "aborted" in result.lower()


def test_a_failed_run_is_reported_as_fatal():
    with mock.patch.object(core, "get_prj_list_modified", return_value=["prj-token-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=None), \
         mock.patch.object(core, "create_wi"), \
         mock.patch.object(core, "conf", _conf()):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    assert core.sync_had_fatal_error() is True


def test_a_clean_run_is_not_reported_as_fatal():
    """Guards the reset: run_sync must clear the flag on entry, or a failure in an
    earlier run (or an earlier test) leaks forward and suppresses Lastrun forever."""
    core.run_failed = True
    with mock.patch.object(core, "get_prj_list_modified", return_value=["prj-token-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")), \
         mock.patch.object(core, "conf", _conf()):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    assert core.sync_had_fatal_error() is False


def test_a_function_reads_live_state_but_an_imported_value_is_frozen():
    """This is why sync_had_fatal_error is a function and not a flag: azure_wi_sync.py
    imports names at module load, so an imported boolean would be frozen at False forever —
    the trap global_errors already falls into."""
    core.run_failed = True
    core.global_errors = 5
    assert sync_had_fatal_error() is True      # function -> live
    assert frozen_counter == 0                 # value    -> frozen at import time
