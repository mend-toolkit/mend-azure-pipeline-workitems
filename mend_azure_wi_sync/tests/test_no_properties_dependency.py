from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(azure_project="Book", reset="false", utc_delta=0)


def test_set_lastrun_no_longer_exists():
    """The write was the hard blocker: a 403 on it exited the run at startup."""
    assert not hasattr(core, "set_lastrun")


def test_the_migration_read_never_exits_and_falls_back_quietly():
    """A 403 here used to exit(-1) at startup. It must now be a shrug."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "get_azure_prj_id", return_value="proj-id"), \
         mock.patch.object(core, "call_azure_api", return_value=({"message": "denied"}, 2)):
        seed = core.migration_seed()
    assert seed == ""


def test_the_migration_read_returns_a_stored_lastrun_when_available():
    payload = ({"value": [{"value": "2026-08-01 00:00:00"}]}, 0)
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "get_azure_prj_id", return_value="proj-id"), \
         mock.patch.object(core, "call_azure_api", return_value=payload):
        assert core.migration_seed() == "2026-08-01 00:00:00"


def test_the_migration_read_is_skipped_when_tag_state_already_exists():
    """main() calls migration_seed() before run_sync, so it must consult tag state itself
    rather than relying on a global some later caller populates."""
    core.project_tag_state = None
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_project_tag_state",
                           return_value={"tok-1": {"lastrun": "2026-08-20 11:00:00"}}), \
         mock.patch.object(core, "call_azure_api") as api:
        assert core.migration_seed() == ""
    api.assert_not_called()


def test_the_migration_read_happens_when_no_project_is_tagged_yet():
    payload = ({"value": [{"value": "2026-08-01 00:00:00"}]}, 0)
    core.project_tag_state = None
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "get_azure_prj_id", return_value="proj-id"), \
         mock.patch.object(core, "call_azure_api", return_value=payload) as api:
        assert core.migration_seed() == "2026-08-01 00:00:00"
    api.assert_called_once()
