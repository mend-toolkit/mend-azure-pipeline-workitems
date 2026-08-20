from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate
from mend_azure_wi_sync.core import sync_had_fatal_error, global_errors as frozen_counter


def _conf():
    return mock.MagicMock(wsproducttoken="", wsprojecttoken="", wsexcludetoken="")


def _reverse_conf():
    # The reverse sync path (update_wi_in_thread / update_wi_for_project) needs a real
    # numeric utc_delta (it lands inside a datetime.timedelta) and a real string for
    # reset/maxlookback (they're .lower()'d and int()'d respectively), unlike the
    # forward-sync-only _conf() above.
    return mock.MagicMock(azure_project="AzureTestProject", utc_delta=0, reset="false",
                          maxlookback="720")


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


def test_a_failed_reverse_sync_wiql_query_sets_the_fatal_flag():
    """A failed WIQL query in the reverse sync must never be treated as 'no more work items
    changed' — that would let the project's revsync tag advance past updates that were
    never actually read."""
    core.synced_projects = [("tok-1", "Prod/Proj", "AzureTestProject")]
    with mock.patch.object(core, "call_azure_api", return_value=({"message": "boom"}, 2)), \
         mock.patch.object(core, "save_project_tag") as save, \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "conf", _reverse_conf()):
        before = core.global_errors
        core.update_wi_in_thread()

    assert core.sync_had_fatal_error() is True
    assert core.global_errors == before + 1
    save.assert_not_called()


def test_a_genuinely_empty_reverse_sync_result_is_not_treated_as_a_failure():
    """A successful WIQL query that legitimately finds nothing changed must not be
    confused with a failed one — that distinction is the entire point of this fix."""
    core.synced_projects = [("tok-1", "Prod/Proj", "AzureTestProject")]
    with mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)), \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "conf", _reverse_conf()):
        before = core.global_errors
        result = core.update_wi_in_thread()

    assert core.sync_had_fatal_error() is False
    assert core.global_errors == before
    assert "Updated 0" in result


def test_run_sync_wires_prepare_enrichment_with_the_resolved_project_list():
    """IMPORTANT 3: prepare_enrichment must actually be called from the non-routed path,
    or every enabled customer silently gets three columns of '-' with all tests green."""
    with mock.patch.object(core, "get_prj_list_modified", return_value=["prj-token-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")), \
         mock.patch.object(core, "prepare_enrichment") as prepare, \
         mock.patch.object(core, "conf", _conf()):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    prepare.assert_called_once_with(["prj-token-1"])


def test_a_failed_reverse_sync_hydration_batch_sets_the_fatal_flag():
    """A failed wit/workitems hydration call must not silently drop that page of updates."""
    core.synced_projects = [("tok-1", "Prod/Proj", "AzureTestProject")]
    wiql_page = ({"workItems": [{"id": 1}]}, 0)
    failed_hydration = ({"message": "boom"}, 2)
    empty_next_page = ({"workItems": []}, 0)
    with mock.patch.object(core, "call_azure_api",
                           side_effect=[wiql_page, failed_hydration, empty_next_page]), \
         mock.patch.object(core, "save_project_tag") as save, \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "conf", _reverse_conf()):
        before = core.global_errors
        core.update_wi_in_thread()

    assert core.sync_had_fatal_error() is True
    assert core.global_errors == before + 1
    save.assert_not_called()
