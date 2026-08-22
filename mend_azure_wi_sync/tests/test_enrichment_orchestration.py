from unittest import mock

from mend_azure_wi_sync import core


def _run_sync_conf(**kw):
    """run_sync needs the token-list branch, so routing must not read as 'true'."""
    return mock.MagicMock(routing="false", wsproducttoken="", wsprojecttoken="",
                          wsexcludetoken="", severity="high", azure_project="Book", **kw)


PROJECTS = [{"uuid": "p-1", "name": "api", "application_uuid": "a-1",
             "application_name": "ProductX", "last_scanned": "", "tags": {}}]


def _run_sync(caplog, conf):
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True), \
         caplog.at_level("INFO"):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    return [r.getMessage() for r in caplog.records]


def test_run_sync_logs_that_epss_and_reachability_are_on(caplog):
    """A pipeline log could not answer 'did enrichment run?' either way, which is what made
    the MEND_AZURETYPE: BUG description loss take three exchanges to diagnose."""
    messages = _run_sync(caplog, _run_sync_conf(epss="true", reachability="true"))
    assert any("EPSS on" in el and "Reachability on" in el for el in messages)


def test_run_sync_logs_that_epss_and_reachability_are_off(caplog):
    """Off is the default and the silent-inert case -- an unexpanded $(MEND_EPSS) /
    $(MEND_REACHABILITY) normalizes to 'false', so the off line is the one that actually
    earns its keep."""
    messages = _run_sync(caplog, _run_sync_conf(epss="false", reachability="false"))
    assert any("EPSS off" in el and "Reachability off" in el for el in messages)


def test_run_sync_logs_each_flag_independently():
    """The whole point of the split: EPSS and Reachability must be reportable, and
    controllable, independently of each other."""
    with mock.patch.object(core, "conf", _run_sync_conf(epss="true", reachability="false")):
        assert core.epss_enabled() is True
        assert core.reachability_enabled() is False
    with mock.patch.object(core, "conf", _run_sync_conf(epss="false", reachability="true")):
        assert core.epss_enabled() is False
        assert core.reachability_enabled() is True
