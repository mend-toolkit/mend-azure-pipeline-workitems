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


def test_an_untagged_project_uses_the_clamped_window():
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", return_value=({"workItems": []}, 0)) as api, \
         mock.patch.object(core, "save_project_tag", return_value=True):
        core.update_wi_for_project("tok-1", "Prod/Proj", TODATE)
    assert "2026-07-21 12:00:00" in api.call_args.kwargs["data"]["query"]


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
