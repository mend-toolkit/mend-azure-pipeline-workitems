"""reconcile_after_sync: the wiring between the forward sync and the closure path.

Every test patches core.reconcile_project rather than exercising it — its interlocks have
their own tests (test_reconcile_apply / test_reconcile_plan) and are deliberately untouched
here. What is under test is the join, the per-project Azure target, and the blast radius.
"""
from unittest import mock

import pytest

from mend_azure_wi_sync import core


def _project(app, name, uuid="u1"):
    return {"uuid": uuid, "name": name, "application_name": app, "application_uuid": "a1",
            "last_scanned": "", "tags": {}}


@pytest.fixture(autouse=True)
def _isolated_globals():
    conf = mock.MagicMock()
    conf.azure_project = "Original"
    with mock.patch.object(core, "conf", conf), \
            mock.patch.object(core, "synced_projects", []), \
            mock.patch.object(core, "global_errors", 0):
        yield conf


def test_a_matched_project_is_reconciled():
    core.synced_projects = [("tok", "ProductX/api", "Platform")]
    project = _project("ProductX", "api")
    with mock.patch.object(core, "fetch_v3_projects", return_value=([project], True)), \
            mock.patch.object(core, "reconcile_project",
                              return_value=(0, 0, 3, 1, 2)) as reconcile:
        core.reconcile_after_sync()
    reconcile.assert_called_once_with(project)


def test_the_join_is_case_folded():
    """Mend spells the application and project names however the user typed them; the tag
    string create_wi records may differ in case. A case mismatch must not look 'unmatched'."""
    core.synced_projects = [("tok", "productx/API", "Platform")]
    with mock.patch.object(core, "fetch_v3_projects",
                           return_value=([_project("ProductX", "api")], True)), \
            mock.patch.object(core, "reconcile_project",
                              return_value=(0, 0, 0, 0, 0)) as reconcile:
        core.reconcile_after_sync()
    assert reconcile.call_count == 1


def test_an_incomplete_mend_project_list_closes_nothing(_isolated_globals):
    """ok=False means projects we failed to read look exactly like projects whose findings
    are all gone. Reconciling on that is a mass-closure event."""
    core.synced_projects = [("tok", "ProductX/api", "Platform")]
    with mock.patch.object(core, "fetch_v3_projects", return_value=([], False)), \
            mock.patch.object(core, "reconcile_project") as reconcile:
        core.reconcile_after_sync()
    reconcile.assert_not_called()


def test_an_unmatched_entry_is_skipped_and_the_others_still_run(caplog):
    core.synced_projects = [("t1", "ProductX/ghost", "Platform"),
                            ("t2", "ProductX/api", "Platform")]
    project = _project("ProductX", "api")
    with mock.patch.object(core, "fetch_v3_projects", return_value=([project], True)), \
            mock.patch.object(core, "reconcile_project",
                              return_value=(0, 0, 1, 0, 0)) as reconcile:
        with caplog.at_level("WARNING"):
            core.reconcile_after_sync()
    reconcile.assert_called_once_with(project)
    assert any("ghost" in rec.message for rec in caplog.records)


def test_the_azure_project_is_set_per_project_and_restored(_isolated_globals):
    """run_sync_routed writes each Mend project to its own Azure project. Closing in the
    wrong one is the worst outcome this feature can produce."""
    core.synced_projects = [("t1", "ProductX/api", "Platform"),
                            ("t2", "ProductX/web", "Payments")]
    projects = [_project("ProductX", "api", "u1"), _project("ProductX", "web", "u2")]
    seen = []

    def _record(project):
        seen.append((project["name"], core.conf.azure_project))
        return (0, 0, 0, 0, 0)

    with mock.patch.object(core, "fetch_v3_projects", return_value=(projects, True)), \
            mock.patch.object(core, "reconcile_project", side_effect=_record):
        core.reconcile_after_sync()
    assert seen == [("api", "Platform"), ("web", "Payments")]
    assert core.conf.azure_project == "Original"


def test_a_failing_project_does_not_abort_the_rest(_isolated_globals):
    core.synced_projects = [("t1", "ProductX/api", "Platform"),
                            ("t2", "ProductX/web", "Payments")]
    projects = [_project("ProductX", "api", "u1"), _project("ProductX", "web", "u2")]
    calls = []

    def _explode_once(project):
        calls.append(project["name"])
        if project["name"] == "api":
            raise RuntimeError("Azure said no")
        return (0, 0, 5, 0, 0)

    before = core.error_count()
    with mock.patch.object(core, "fetch_v3_projects", return_value=(projects, True)), \
            mock.patch.object(core, "reconcile_project", side_effect=_explode_once):
        core.reconcile_after_sync()
    assert calls == ["api", "web"]
    assert core.error_count() == before + 1
    assert core.conf.azure_project == "Original"


def test_a_failure_inside_the_body_never_propagates(_isolated_globals):
    """A failure to close must not cost the forward sync that already succeeded."""
    core.synced_projects = [("t1", "ProductX/api", "Platform")]
    before = core.error_count()
    with mock.patch.object(core, "fetch_v3_projects", side_effect=RuntimeError("boom")):
        core.reconcile_after_sync()
    assert core.error_count() == before + 1
    assert core.conf.azure_project == "Original"


def test_the_summary_reports_the_totals(caplog):
    core.synced_projects = [("t1", "ProductX/api", "Platform"),
                            ("t2", "ProductX/ghost", "Platform")]
    with mock.patch.object(core, "fetch_v3_projects",
                           return_value=([_project("ProductX", "api")], True)), \
            mock.patch.object(core, "reconcile_project", return_value=(0, 0, 4, 2, 1)):
        with caplog.at_level("INFO"):
            core.reconcile_after_sync()
    summary = [rec.message for rec in caplog.records if "Reconciliation summary" in rec.message]
    assert len(summary) == 1
    assert "4 work item(s) closed" in summary[0]
    assert "2 reopened" in summary[0]
    assert "1 already closed" in summary[0]
    assert "1 project(s) reconciled, 1 unmatched" in summary[0]


def test_it_is_wired_into_the_run_flow():
    """A dormant function with no caller is the bug this change exists to fix."""
    import inspect
    from mend_azure_wi_sync import azure_wi_sync
    source = inspect.getsource(azure_wi_sync.main)
    assert "reconcile_after_sync()" in source
    assert source.index("run_sync(") < source.index("reconcile_after_sync()")
