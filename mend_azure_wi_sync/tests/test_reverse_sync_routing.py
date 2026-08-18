from unittest import mock

from mend_azure_wi_sync import core


def test_reverse_sync_visits_every_routed_target():
    core.routed_targets = ["Platform", "Tools"]
    seen = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="true", utc_delta=0)), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda: seen.append(core.conf.azure_project)), \
         mock.patch.object(core, "set_lastrun") as set_lastrun:
        core.update_wi_in_thread()
    assert seen == ["Platform", "Tools"]
    # Neither target failed, so both windows must be closed.
    assert set_lastrun.call_count == 2


def test_reverse_sync_restores_the_original_project():
    core.routed_targets = ["Platform", "Tools"]
    conf = mock.MagicMock(azure_project="Bookkeeping", routing="true", utc_delta=0)
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project"), \
         mock.patch.object(core, "set_lastrun"):
        core.update_wi_in_thread()
    assert conf.azure_project == "Bookkeeping"


def test_reverse_sync_without_routing_runs_once():
    core.routed_targets = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="false", utc_delta=0)), \
         mock.patch.object(core, "update_wi_for_project") as inner, \
         mock.patch.object(core, "set_lastrun") as set_lastrun:
        core.update_wi_in_thread()
    assert inner.call_count == 1
    # The non-routed path returns update_wi_for_project() directly; it has no per-target
    # loop and therefore no Lastrun write of its own here.
    set_lastrun.assert_not_called()


def test_reverse_sync_skips_targets_the_forward_sync_did_not_reach():
    """routed_targets only contains projects that synced successfully, so a failed
    target is not walked with a ten-year window."""
    core.routed_targets = ["Platform"]
    seen = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="true", utc_delta=0)), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda: seen.append(core.conf.azure_project)), \
         mock.patch.object(core, "set_lastrun"):
        core.update_wi_in_thread()
    assert seen == ["Platform"]


def test_a_targets_failed_reverse_sync_does_not_advance_its_own_lastrun():
    """CRITICAL 1: update_wi_for_project sets run_failed on a WIQL failure, a hydration
    failure, or any exception. If the per-target set_lastrun() call after it is
    unguarded, that target's watermark still advances even though its reverse sync
    never completed — and the global watermark being withheld (azure_wi_sync.py) cannot
    recover it, because this target's own window already closed.

    Two targets: the first's update_wi_for_project sets run_failed; the second's does
    not. set_lastrun must be called for the second target only.
    """
    core.routed_targets = ["Platform", "Tools"]
    conf = mock.MagicMock(azure_project="Bookkeeping", routing="true", utc_delta=0)

    def fake_update():
        if core.conf.azure_project == "Platform":
            core.run_failed = True
        return "result"

    lastrun_targets = []
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project", side_effect=fake_update), \
         mock.patch.object(core, "set_lastrun",
                           side_effect=lambda *a, **k: lastrun_targets.append(core.conf.azure_project)):
        core.update_wi_in_thread()

    assert lastrun_targets == ["Tools"]
