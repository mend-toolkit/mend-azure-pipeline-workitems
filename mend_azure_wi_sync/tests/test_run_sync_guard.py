from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(wsproducttoken="", wsprojecttoken="", wsexcludetoken="")


def test_run_sync_aborts_when_existing_items_cannot_be_read():
    """A failed WIQL query must never be treated as 'this project has no work items yet'."""
    with mock.patch.object(core, "get_prj_list_modified", return_value=["prj-token-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=None), \
         mock.patch.object(core, "create_wi") as create_wi, \
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
         mock.patch.object(core, "create_wi", return_value="done"), \
         mock.patch.object(core, "conf", _conf()):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    assert core.sync_had_fatal_error() is False


def test_the_flag_is_visible_through_the_flat_import_path():
    """Production imports `from core import sync_had_fatal_error` (azure_wi_sync.py:8-9),
    not the package path the other tests use. That is the path the import-by-value trap
    lives on, so it is the one worth proving."""
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(core.__file__)))
    from core import sync_had_fatal_error as flat_accessor
    core.run_failed = True
    assert flat_accessor() is True
    core.run_failed = False
    assert flat_accessor() is False
