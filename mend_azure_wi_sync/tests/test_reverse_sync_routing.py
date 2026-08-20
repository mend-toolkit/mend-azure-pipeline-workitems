from unittest import mock

from mend_azure_wi_sync import core

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
