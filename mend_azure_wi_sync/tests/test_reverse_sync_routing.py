from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate

# The reverse sync used to be scoped per Azure project (visiting every project the
# forward sync routed to, via the now-removed `routed_targets` list, and closing each
# target's window with a single project-wide Lastrun property). It is now scoped per
# Mend project: create_wi appends (token, "Product/Project", azure_project) to
# `synced_projects` on success, and update_wi_in_thread walks that list, scoping each
# WIQL query to the project's own tag and advancing only that project's revsync tag
# (core.update_wi_for_project). These tests are rewritten against that contract; the
# old per-Azure-project / per-target Lastrun assertions are deliberately obsolete
# (spec decision 6).


def _conf(**kw):
    base = dict(azure_project="Bookkeeping", utc_delta=0)
    base.update(kw)
    return mock.MagicMock(**base)


def test_reverse_sync_visits_every_synced_mend_project():
    core.synced_projects = [("tok-1", "Prod/Platform", "Platform"),
                            ("tok-2", "Prod/Tools", "Tools")]
    seen = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append((tok, tag)) or "ok"):
        core.update_wi_in_thread()
    assert seen == [("tok-1", "Prod/Platform"), ("tok-2", "Prod/Tools")]


def test_reverse_sync_points_conf_azure_project_at_each_targets_own_azure_project():
    core.synced_projects = [("tok-1", "Prod/Platform", "Platform"),
                            ("tok-2", "Prod/Tools", "Tools")]
    seen_azure_project = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen_azure_project.append(
                               core.conf.azure_project) or "ok"):
        core.update_wi_in_thread()
    assert seen_azure_project == ["Platform", "Tools"]


def test_reverse_sync_restores_the_original_project():
    core.synced_projects = [("tok-1", "Prod/Platform", "Platform"),
                            ("tok-2", "Prod/Tools", "Tools")]
    conf = _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok"):
        core.update_wi_in_thread()
    assert conf.azure_project == "Bookkeeping"


def test_reverse_sync_is_skipped_when_nothing_synced_this_run():
    core.synced_projects = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project") as inner:
        result = core.update_wi_in_thread()
    inner.assert_not_called()
    assert "skipped" in result.lower()


def test_reverse_sync_skips_a_target_with_an_unresolved_project_tag():
    """An empty, leading-slash, or trailing-slash tag means the product/project name
    failed to resolve. Querying with it would match nothing, or (worse) everything —
    so that target must be skipped rather than passed to update_wi_for_project."""
    core.synced_projects = [("tok-bad-1", "", "Platform"),
                            ("tok-bad-2", "/Proj", "Platform"),
                            ("tok-bad-3", "Prod/", "Platform"),
                            ("tok-good", "Prod/Proj", "Platform")]
    seen = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-good"]


def test_the_per_target_results_are_joined_into_one_report():
    """update_wi_for_project owns advancing its own project's revsync tag on success or
    withholding it on failure (see test_reverse_sync_state.py); update_wi_in_thread's
    job is just to call it once per synced Mend project and report each result — it no
    longer gates one target's watermark write on another's outcome, because there is no
    longer a single shared watermark to gate."""
    core.synced_projects = [("tok-1", "Prod/Platform", "Platform"),
                            ("tok-2", "Prod/Tools", "Tools")]
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=["Updated 1 work item(s) for Prod/Platform",
                                       "Updated 0 work item(s) for Prod/Tools"]):
        result = core.update_wi_in_thread()
    assert "Prod/Platform: Updated 1 work item(s) for Prod/Platform" in result
    assert "Prod/Tools: Updated 0 work item(s) for Prod/Tools" in result


def test_a_failed_targets_reverse_sync_does_not_block_a_healthy_targets_watermark():
    """Cross-project failure isolation. update_wi_for_project (unmocked here, so this
    exercises the real function) advances a project's own revsync tag independently of
    any other project in the same run -- there is no longer a single shared watermark for
    one failure to withhold from everyone else."""
    core.synced_projects = [("tok-fail", "Prod/Fail", "AzureFail"),
                            ("tok-ok", "Prod/Ok", "AzureOk")]

    def fake_call_azure_api(*a, **kw):
        if kw.get("project") == "AzureFail":
            return {"message": "boom"}, 2
        return {"workItems": []}, 0

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "call_azure_api", side_effect=fake_call_azure_api), \
         mock.patch.object(core, "save_project_tag", return_value=True) as save:
        core.update_wi_in_thread()

    assert save.call_count == 1
    assert save.call_args.args[0] == "tok-ok"


def test_the_non_routed_path_populates_synced_projects_so_the_reverse_sync_runs():
    """Guards the wiring the old (now-removed) test_reverse_sync_without_routing_runs_once
    locked down: a non-routed run_sync must leave something in synced_projects for
    update_wi_in_thread to act on, or the reverse sync silently no-ops every run.
    create_wi is mocked here -- its own append contract (token, "Product/Project",
    conf.azure_project), guarded on `not item_failed`, is covered directly against the
    real function by test_create_wi_verdict.py -- but its side_effect performs that same
    append, so this test exercises the real run_sync -> synced_projects ->
    update_wi_in_thread wiring end to end."""
    conf = mock.MagicMock(routing="false", wsproducttoken="", wsprojecttoken="",
                          wsexcludetoken="", azure_project="Bookkeeping", utc_delta=0)

    def fake_create_wi(token, *a, **kw):
        core.synced_projects.append((token, f"Prod/{token}", conf.azure_project))
        return syncstate.VERDICT_OK, "done"

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=["tok-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         mock.patch.object(core, "create_wi", side_effect=fake_create_wi):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    assert core.synced_projects  # non-empty: the reverse sync now has something to do

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok") as inner:
        result = core.update_wi_in_thread()
    inner.assert_called_once()
    assert "skipped" not in result.lower()
