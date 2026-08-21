from unittest import mock

import pytest

from mend_azure_wi_sync import azure_wi_sync, core


@pytest.mark.live
def test_load_wi_json():
    """Hits the live Azure DevOps API. Requires WS_AZUREURI / WS_AZUREPAT / WS_AZUREPROJECT."""
    assert core.load_wi_json()


def test_globals_are_clean_at_test_start():
    assert core.exist_wis == []
    core.exist_wis.append({"dirty": {1: "tag"}})


def test_globals_are_clean_for_the_next_test():
    """Only meaningful because the previous test dirtied exist_wis."""
    assert core.exist_wis == []


def test_incremental_sync_notice_is_info_not_warning():
    """Incremental sync (MEND_RESET=false) is the normal, intended mode -- logging it at
    warning level trains operators to ignore warnings. It must be an info line."""
    fake_conf = mock.MagicMock(reset="false", azure_custom="", utc_delta=0)
    with mock.patch.object(azure_wi_sync, "conf", fake_conf), \
         mock.patch.object(azure_wi_sync, "startup", return_value=fake_conf), \
         mock.patch.object(azure_wi_sync, "check_patterns", return_value=[]), \
         mock.patch.object(azure_wi_sync, "load_wi_json", return_value=("Task", [{}])), \
         mock.patch.object(azure_wi_sync, "migration_seed", return_value=""), \
         mock.patch.object(azure_wi_sync, "run_sync", return_value="ok"), \
         mock.patch.object(azure_wi_sync, "update_wi_in_thread", return_value="ok"), \
         mock.patch.object(azure_wi_sync, "sync_had_fatal_error", return_value=False), \
         mock.patch.object(azure_wi_sync, "error_count", return_value=0), \
         mock.patch.object(azure_wi_sync.logger, "info") as info, \
         mock.patch.object(azure_wi_sync.logger, "warning") as warning:
        azure_wi_sync.main()

    info_msgs = [c.args[0] for c in info.call_args_list if c.args]
    warning_msgs = [c.args[0] for c in warning.call_args_list if c.args]
    assert any("MEND_RESET parameter set to FALSE" in m for m in info_msgs)
    assert not any("MEND_RESET parameter set to FALSE" in m for m in warning_msgs)
