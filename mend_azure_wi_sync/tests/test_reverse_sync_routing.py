from unittest import mock

from mend_azure_wi_sync import core


def test_reverse_sync_visits_every_routed_target():
    core.routed_targets = ["Platform", "Tools"]
    seen = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="true")), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda: seen.append(core.conf.azure_project)):
        core.update_wi_in_thread()
    assert seen == ["Platform", "Tools"]


def test_reverse_sync_restores_the_original_project():
    core.routed_targets = ["Platform", "Tools"]
    conf = mock.MagicMock(azure_project="Bookkeeping", routing="true")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project"):
        core.update_wi_in_thread()
    assert conf.azure_project == "Bookkeeping"


def test_reverse_sync_without_routing_runs_once():
    core.routed_targets = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="false")), \
         mock.patch.object(core, "update_wi_for_project") as inner:
        core.update_wi_in_thread()
    assert inner.call_count == 1


def test_reverse_sync_skips_targets_the_forward_sync_did_not_reach():
    """routed_targets only contains projects that synced successfully, so a failed
    target is not walked with a ten-year window."""
    core.routed_targets = ["Platform"]
    seen = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Bookkeeping",
                                                        routing="true")), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda: seen.append(core.conf.azure_project)):
        core.update_wi_in_thread()
    assert seen == ["Platform"]
