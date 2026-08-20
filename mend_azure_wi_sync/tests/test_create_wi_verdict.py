from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate


def _conf():
    return mock.MagicMock(azure_type="Task", dependency="false", wsalert="true",
                          enrichment="false", reponame="", routing="false",
                          ws_user_key="uk-123")


def test_a_failed_mend_fetch_verdicts_failed():
    """The regression test for the whole design. If this ever returns OK, every affected
    project's watermark advances past findings that were never read."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", return_value=None):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED
    assert "tok-1" in message


def test_a_genuinely_empty_window_verdicts_ok():
    # get_ingnored_alerts/get_prj_lib_hierarchy/get_prj_licenses/get_lib_locations are
    # defined *inside* create_wi (closures over prj_token), not module attributes, so they
    # cannot be mock.patch.object'd on `core`. fetch_prj_policy returning a project with no
    # libraries (ws_prj[2:] == []) means the create/update loop body never runs, so the only
    # thing that needs to succeed is the underlying call_ws_api plumbing those helpers share.
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", return_value=["Prod", "Proj"]), \
         mock.patch.object(core, "call_ws_api", return_value='{"libraries": []}'):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_OK
    assert "No Task work items" in message


def test_an_unexpected_exception_verdicts_failed():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", side_effect=Exception("boom")):
        verdict, _ = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                    "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED
