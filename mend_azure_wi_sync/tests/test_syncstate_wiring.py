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
    yield
    core.project_tag_state = None
    core.tag_state_available = True
    core.TAG_WARNED = False


def _conf(**kw):
    base = dict(routing="false", wsproducttoken="", wsprojecttoken="", wsexcludetoken="",
                reset="false", maxlookback="720")
    base.update(kw)
    return mock.MagicMock(**base)


def _run(conf, state, modified, verdict=syncstate.VERDICT_OK):
    core.project_tag_state = state
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=modified) as modified_call, \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi", return_value=(verdict, "done")) as create, \
         mock.patch.object(core, "apply_tag_ops") as ops:
        core.run_sync(st_date="", end_date=TODATE, custom_flds=[], wi_type="Task")
    return modified_call, create, ops


def test_the_modified_query_uses_the_newest_watermark_as_its_floor():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    modified_call, _, _ = _run(_conf(), state, ["tok-1"])
    assert modified_call.call_args.args[0] == "2026-08-20 11:00:00"


def test_a_failed_project_is_retried_even_when_mend_says_unmodified():
    """The defect this whole design closes."""
    state = {"tok-stale": {"lastrun": "2026-01-01 00:00:00",
                           "failed": "2026-08-19 11:00:00"}}
    _, create, _ = _run(_conf(), state, [])
    assert [c.args[0] for c in create.call_args_list] == ["tok-stale"]


def test_each_project_is_fetched_with_its_own_clamped_window():
    state = {"tok-recent": {"lastrun": "2026-08-20 11:00:00"}}
    _, create, _ = _run(_conf(), state, ["tok-recent", "tok-new"])
    starts = {c.args[0]: c.args[1] for c in create.call_args_list}
    assert starts["tok-recent"] == "2026-08-20 11:00:00"
    assert starts["tok-new"] == "2026-07-21 12:00:00"      # clamped, not the floor


def test_success_advances_that_projects_watermark_and_clears_its_retry_flag():
    _, _, ops = _run(_conf(), {}, ["tok-1"])
    ops.assert_called_once_with("tok-1", [
        ("save", syncstate.TAG_LASTRUN, TODATE),
        ("remove", syncstate.TAG_FAILED, ""),
    ])


def test_failure_records_the_retry_flag_and_leaves_the_watermark():
    _, _, ops = _run(_conf(), {}, ["tok-1"], verdict=syncstate.VERDICT_FAILED)
    ops.assert_called_once_with("tok-1", [("save", syncstate.TAG_FAILED, TODATE)])


def test_reset_ignores_stored_state_for_both_selection_and_windows():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    modified_call, create, _ = _run(_conf(reset="true"), state, ["tok-1"])
    assert modified_call.call_args.args[0] == "2016-08-22 12:00:00"
    assert create.call_args_list[0].args[1] == "2016-08-22 12:00:00"


def test_a_failed_project_that_is_excluded_is_not_synced():
    """Exclusion must win over retry: a stale failure tag must not defeat MEND_EXCLUDETOKEN."""
    state = {"tok-failed": {"lastrun": "2026-01-01 00:00:00", "failed": "2026-08-19 11:00:00"}}
    _, create, _ = _run(_conf(wsexcludetoken="tok-failed"), state, [])
    assert create.call_args_list == []


def test_a_failed_project_outside_product_project_scope_is_not_synced():
    """A retry candidate outside a scoped MEND_PROJECTTOKEN pilot must not evaporate the scope."""
    state = {"tok-failed": {"lastrun": "2026-01-01 00:00:00", "failed": "2026-08-19 11:00:00"}}
    _, create, _ = _run(_conf(wsprojecttoken="tok-other"), state, [])
    assert create.call_args_list == []
