"""The 3.0 run flow: selection by UUID, one severity floor for creation AND closure, and the
partial-read interlock. Replaces the 1.4 window/watermark wiring these paths used to carry."""
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.source3 import severity_floor


def _project(uuid, name, app_uuid="a-1", app_name="ProductX"):
    return {"uuid": uuid, "name": name, "application_uuid": app_uuid,
            "application_name": app_name, "last_scanned": "", "tags": {}}


PROJECTS = [_project("p-1", "api"),
            _project("p-2", "web"),
            _project("p-3", "billing", app_uuid="a-2", app_name="ProductY")]


def _conf(**kw):
    base = dict(routing="false", wsproducttoken="", wsprojecttoken="", wsexcludetoken="",
                severity="high", azure_project="Book", reponame="", azure_area="",
                epss="false", reachability="false")
    base.update(kw)
    return mock.MagicMock(**base)


def _run(conf, projects=PROJECTS, projects_ok=True, desired=({}, True)):
    """Run the token-list path with creation and closure stubbed, returning what each saw."""
    seen = {"created": [], "closed": [], "floors": []}

    def _fetch(uuid, floor):
        seen["floors"].append(("fetch", floor))
        return desired

    def _create(project, des, custom_flds, wi_type):
        seen["created"].append(project["uuid"])
        return (1, 0, 0)

    def _reconcile(project, floor=None, desired=None, ok=None):
        seen["closed"].append((project["uuid"], floor, ok, id(desired)))
        seen["floors"].append(("reconcile", floor))
        return (0, 0, 0, 0, 0)

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_v3_projects", return_value=(projects, projects_ok)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "fetch_v3_desired", side_effect=_fetch), \
         mock.patch.object(core, "create_wi_v3", side_effect=_create), \
         mock.patch.object(core, "reconcile_project", side_effect=_reconcile):
        seen["result"] = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    return seen


# --- selection -------------------------------------------------------------------------

def test_no_tokens_selects_every_project():
    assert _run(_conf())["created"] == ["p-1", "p-2", "p-3"]


def test_a_project_uuid_selects_that_project():
    assert _run(_conf(wsprojecttoken="p-2"))["created"] == ["p-2"]


def test_an_application_uuid_selects_every_project_in_it():
    assert _run(_conf(wsproducttoken="a-1"))["created"] == ["p-1", "p-2"]


def test_exclude_is_subtracted_last():
    seen = _run(_conf(wsproducttoken="a-1", wsexcludetoken="p-1"))
    assert seen["created"] == ["p-2"]


def test_an_unresolved_uuid_aborts_the_run_and_names_the_variable(caplog):
    """A stale 1.4 token selects nothing, which reads as 'no work to do' -- and with closure
    live that reads as 'everything was remediated'. It must abort, not sync a partial scope."""
    with caplog.at_level("ERROR"):
        seen = _run(_conf(wsprojecttoken="p-2,not-a-uuid"))
    assert seen["created"] == []
    assert seen["closed"] == []
    assert "aborted" in seen["result"].lower()
    assert "not-a-uuid" in seen["result"]
    assert core.sync_had_fatal_error() is True
    assert any("not-a-uuid" in r.getMessage() and "MEND_PROJECTTOKEN" in r.getMessage()
               for r in caplog.records)


def test_an_unresolved_exclude_uuid_also_aborts(caplog):
    """An exclusion that resolves to nothing means work items are about to be created -- and
    closed -- in a project the operator believed was out of scope."""
    with caplog.at_level("ERROR"):
        seen = _run(_conf(wsexcludetoken="ghost"))
    assert seen["created"] == []
    assert any("ghost" in r.getMessage() and "MEND_EXCLUDETOKEN" in r.getMessage()
               for r in caplog.records)


# --- one floor for both halves ---------------------------------------------------------

def test_creation_and_closure_receive_the_identical_floor():
    """THE invariant of this task. If the floor that filters `desired` for creation differs
    from the floor closure reads at, every finding between the two thresholds is created,
    closed and re-created every run -- flapping forever."""
    seen = _run(_conf(severity="medium"))
    floors = {floor for _, floor in seen["floors"]}
    assert floors == {severity_floor("medium")} == {4.0}
    assert [(uuid, floor) for uuid, floor, _, _ in seen["closed"]] == [
        ("p-1", 4.0), ("p-2", 4.0), ("p-3", 4.0)]


def test_closure_reads_the_very_snapshot_creation_wrote_from():
    """Same floor is necessary but not sufficient: both halves are handed ONE `desired`, so
    they cannot disagree even about a finding that changed mid-run."""
    desired = ({("vulnerability", "log4j-core"): {"findings": [], "licenses": []}}, True)
    seen = _run(_conf(), projects=[PROJECTS[0]], desired=desired)
    assert seen["closed"][0][3] == id(desired[0])
    # One read per project, not one for creation and another for closure.
    assert [kind for kind, _ in seen["floors"]] == ["fetch", "reconcile"]


def test_an_unparseable_severity_falls_back_to_the_default_floor_on_both_halves():
    seen = _run(_conf(severity="$(MEND_SEVERITY)"))
    assert {floor for _, floor in seen["floors"]} == {severity_floor("")} == {7.0}


# --- interlocks ------------------------------------------------------------------------

def test_a_partial_mend_read_still_creates_but_closes_nothing():
    """ok=False reaches reconcile_project unchanged; the closure skip lives there."""
    seen = _run(_conf(), projects=[PROJECTS[0]], desired=({}, False))
    assert seen["created"] == ["p-1"]
    assert seen["closed"][0][2] is False


def test_synced_projects_records_the_azure_project_each_mend_project_was_written_to():
    conf = _conf()
    _run(conf, projects=[PROJECTS[0]])
    assert core.synced_projects == [("p-1", "ProductX/api", conf.azure_project)]


def test_reconciliation_runs_inside_the_forward_sync():
    """The closure pass is no longer a separate end-of-run sweep at its own threshold: it runs
    per project, right after that project's creation, from the same read."""
    import inspect
    source = inspect.getsource(core.sync_project_v3)
    assert source.index("create_wi_v3(") < source.index("reconcile_project(")
    assert "floor=floor" in source and "desired=desired" in source and "ok=ok" in source
