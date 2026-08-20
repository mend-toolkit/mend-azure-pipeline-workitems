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
    core.global_errors = 0
    core.run_failed = False
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


def test_the_modified_query_uses_the_oldest_watermark_as_its_floor():
    """Was the newest. A project selected but never reached carries no tag, so the newest
    watermark can advance the org sweep past a window nobody read and Mend can never report
    that project modified again."""
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"},
             "tok-2": {"lastrun": "2026-08-19 08:00:00"}}
    modified_call, _, _ = _run(_conf(), state, ["tok-1"])
    assert modified_call.call_args.args[0] == "2026-08-19 08:00:00"


def test_a_stale_watermark_keeps_its_wide_window_and_says_so(caplog):
    """The persistently-failing project. Narrowing its window to MEND_MAXLOOKBACK would skip
    everything raised since it froze, and the OK verdict on the run where the operator finally
    fixes the cause would then close that gap for good."""
    state = {"tok-frozen": {"lastrun": "2026-06-01 00:00:00"}}
    with caplog.at_level("WARNING"):
        _, create, _ = _run(_conf(), state, ["tok-frozen"])
    assert create.call_args.args[1] == "2026-06-01 00:00:00"
    assert any("MEND_MAXLOOKBACK" in r.getMessage() and "tok-frozen" in r.getMessage()
               for r in caplog.records)


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


def test_success_on_a_healthy_project_only_advances_the_watermark():
    """No retry tag was stored, so there is nothing to remove. The unconditional remove risked
    an error on every healthy run, which would falsely report the sync state unavailable and
    spend the once-per-run warning that a genuine save failure needs."""
    _, _, ops = _run(_conf(), {}, ["tok-1"])
    ops.assert_called_once_with("tok-1", [("save", syncstate.TAG_LASTRUN, TODATE)])


def test_success_after_a_failure_clears_the_retry_flag_using_the_stored_value():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00", "failed": "2026-08-19 11:00:00"}}
    _, _, ops = _run(_conf(), state, ["tok-1"])
    ops.assert_called_once_with("tok-1", [
        ("save", syncstate.TAG_LASTRUN, TODATE),
        ("remove", syncstate.TAG_FAILED, "2026-08-19 11:00:00"),
    ])


def test_failure_records_the_retry_flag_and_leaves_the_watermark():
    _, _, ops = _run(_conf(), {}, ["tok-1"], verdict=syncstate.VERDICT_FAILED)
    ops.assert_called_once_with("tok-1", [("save", syncstate.TAG_FAILED, TODATE)])


def test_a_failed_verdict_is_visible_in_the_run(caplog):
    """create_wi's message stays byte-identical, so a project whose every work item write was
    rejected still returns a success-shaped "0 ... work items" line. Without an error here the
    run printed "Sync process completed successfully" and exited 0, and the only trace of the
    failure was a tag in Mend."""
    core.global_errors = 0
    with caplog.at_level("ERROR"):
        _run(_conf(), {}, ["tok-1"], verdict=syncstate.VERDICT_FAILED)
    assert core.error_count() == 1
    assert any("tok-1" in r.getMessage() and "retried" in r.getMessage()
               for r in caplog.records)


def test_one_projects_failure_does_not_fail_the_whole_run():
    """Deliberate: run_failed would withhold nothing here (state is per project now) but would
    turn any single flaky repo into a red pipeline and, worse, hide which projects did advance."""
    core.run_failed = False
    _run(_conf(), {}, ["tok-1"], verdict=syncstate.VERDICT_FAILED)
    assert core.sync_had_fatal_error() is False


def test_a_successful_verdict_adds_no_errors():
    core.global_errors = 0
    _run(_conf(), {}, ["tok-1"])
    assert core.error_count() == 0


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


ROUTE_TAGS_PAYMENTS = [{"key": "azure-project", "value": "Payments"},
                       {"key": "azure-repo", "value": "api"},
                       {"key": "azure-branch", "value": "refs/heads/main"}]


def test_the_routed_path_applies_tag_ops_per_mend_project():
    core.project_tag_state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    with mock.patch.object(core, "conf", _conf(routing="true", branches="main",
                                               azure_project="Book", azure_area="", reponame="")), \
         mock.patch.object(core, "fetch_project_tags",
                           return_value={"tok-1": ROUTE_TAGS_PAYMENTS}), \
         mock.patch.object(core, "list_azure_projects", return_value=["Payments"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi",
                           return_value=(syncstate.VERDICT_OK, "done")) as create, \
         mock.patch.object(core, "apply_tag_ops") as ops:
        core.run_sync_routed(["tok-1"], "2026-08-01 00:00:00", TODATE, [], "Task")
    assert create.call_args.args[1] == "2026-08-20 11:00:00"
    ops.assert_called_once_with("tok-1", [("save", syncstate.TAG_LASTRUN, TODATE)])


def test_a_failed_project_is_retried_under_routing():
    """Without this the retry queue is dead on the path the client actually uses: run_sync_routed
    received raw modified_projects and never unioned the failure tags."""
    core.project_tag_state = {"tok-stale": {"lastrun": "2026-01-01 00:00:00",
                                           "failed": "2026-08-19 11:00:00"}}
    with mock.patch.object(core, "conf", _conf(routing="true", branches="main",
                                               azure_project="Book", azure_area="", reponame="")), \
         mock.patch.object(core, "get_prj_list_modified", return_value=[]), \
         mock.patch.object(core, "fetch_project_tags",
                           return_value={"tok-stale": ROUTE_TAGS_PAYMENTS}), \
         mock.patch.object(core, "list_azure_projects", return_value=["Payments"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi",
                           return_value=(syncstate.VERDICT_OK, "done")) as create, \
         mock.patch.object(core, "apply_tag_ops"):
        core.run_sync(st_date="", end_date=TODATE, custom_flds=[], wi_type="Task")
    assert [c.args[0] for c in create.call_args_list] == ["tok-stale"]


def test_an_unroutable_project_gets_no_tag_writes_at_all():
    """Retrying a project whose destination does not exist cannot succeed, so it must never
    enter the retry queue — a human has to fix the tag first."""
    route_tags_missing = [{"key": "azure-project", "value": "Missing"},
                          {"key": "azure-repo", "value": "api"},
                          {"key": "azure-branch", "value": "refs/heads/main"}]
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf(routing="true", branches="main",
                                               azure_project="Book", azure_area="", reponame="")), \
         mock.patch.object(core, "fetch_project_tags", return_value={"tok-1": route_tags_missing}), \
         mock.patch.object(core, "list_azure_projects", return_value=["Payments"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi") as create, \
         mock.patch.object(core, "apply_tag_ops") as ops:
        core.run_sync_routed(["tok-1"], "2026-08-01 00:00:00", TODATE, [], "Task")
    create.assert_not_called()
    ops.assert_not_called()


def test_a_failed_project_that_is_excluded_is_not_synced_under_routing():
    """Permission beats retry under routing too: a stale failure tag alone must not defeat
    MEND_EXCLUDETOKEN once routing is on. The retry union happens before the routed narrowing
    block (Step 3a), so this locks in that the routed narrowing still applies to retried tokens."""
    core.project_tag_state = {"tok-failed": {"lastrun": "2026-01-01 00:00:00",
                                             "failed": "2026-08-19 11:00:00"}}
    with mock.patch.object(core, "conf", _conf(routing="true", branches="main",
                                               azure_project="Book", azure_area="", reponame="",
                                               wsexcludetoken="tok-failed")), \
         mock.patch.object(core, "get_prj_list_modified", return_value=[]), \
         mock.patch.object(core, "fetch_project_tags",
                           return_value={"tok-failed": ROUTE_TAGS_PAYMENTS}), \
         mock.patch.object(core, "list_azure_projects", return_value=["Payments"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi",
                           return_value=(syncstate.VERDICT_OK, "done")) as create, \
         mock.patch.object(core, "apply_tag_ops"):
        core.run_sync(st_date="", end_date=TODATE, custom_flds=[], wi_type="Task")
    assert create.call_args_list == []


def test_a_failed_project_outside_scope_is_not_synced_under_routing():
    """Same guarantee, the MEND_PROJECTTOKEN-scope variant: a retry candidate outside a scoped
    pilot must not evaporate the scope once routing is on."""
    core.project_tag_state = {"tok-failed": {"lastrun": "2026-01-01 00:00:00",
                                             "failed": "2026-08-19 11:00:00"}}
    with mock.patch.object(core, "conf", _conf(routing="true", branches="main",
                                               azure_project="Book", azure_area="", reponame="",
                                               wsprojecttoken="tok-other")), \
         mock.patch.object(core, "get_prj_list_modified", return_value=[]), \
         mock.patch.object(core, "fetch_project_tags",
                           return_value={"tok-failed": ROUTE_TAGS_PAYMENTS}), \
         mock.patch.object(core, "list_azure_projects", return_value=["Payments"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "prepare_enrichment"), \
         mock.patch.object(core, "create_wi",
                           return_value=(syncstate.VERDICT_OK, "done")) as create, \
         mock.patch.object(core, "apply_tag_ops"):
        core.run_sync(st_date="", end_date=TODATE, custom_flds=[], wi_type="Task")
    assert create.call_args_list == []
