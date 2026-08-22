from unittest import mock

from mend_azure_wi_sync import core


def _conf(routing="true", exclude="", product="", project=""):
    return mock.MagicMock(routing=routing, branches="main,master", azure_project="Bookkeeping",
                          reponame="", azure_area="", severity="high", epss="false",
                          reachability="false", wsproducttoken=product, wsprojecttoken=project,
                          wsexcludetoken=exclude)


def _project(uuid, name, tags, app_uuid="a-1", app_name="ProductX"):
    return {"uuid": uuid, "name": name, "application_uuid": app_uuid,
            "application_name": app_name, "last_scanned": "", "tags": tags}


def _tags(azure_project, repo="api", branch="refs/heads/main"):
    return {"azure-project": [azure_project], "azure-repo": [repo], "azure-branch": [branch]}


PROJECTS = [_project("p-a", "api", _tags("Platform")),
            _project("p-b", "cli", _tags("Tools", repo="cli")),
            _project("p-c", "untagged", {})]


def _patches(conf, projects=PROJECTS, known={"Platform", "Tools"}):
    """Start the common patches; every test using this must call mock.patch.stopall()."""
    for p in (mock.patch.object(core, "conf", conf),
              mock.patch.object(core, "fetch_v3_projects", return_value=(projects, True)),
              mock.patch.object(core, "list_azure_projects", return_value=known)):
        p.start()


def test_routing_off_never_reads_the_routing_tags():
    with mock.patch.object(core, "conf", _conf(routing="false")), \
         mock.patch.object(core, "fetch_v3_projects", return_value=(PROJECTS, True)), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True), \
         mock.patch.object(core, "list_azure_projects") as azure_projects:
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    azure_projects.assert_not_called()


def test_routing_on_syncs_each_azure_target_once():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]) as exist, \
         mock.patch.object(core, "sync_project_v3", return_value=True):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    # exist_wis is per AZURE project: read once per target, not once per Mend project, and
    # ALWAYS re-read when the target changes -- matching (and now closing) against another
    # project's work items is the failure this guards.
    assert exist.call_count == 2
    assert "2 of 3" in result


def test_creation_and_closure_both_run_against_the_projects_own_azure_target():
    """conf.azure_project is re-pointed per target, and BOTH halves of the project's sync see
    it -- a leak would close work items in the wrong Azure project."""
    conf = _conf()
    seen = []

    def _sync(project, floor, custom_flds, wi_type):
        seen.append((project["uuid"], conf.azure_project))
        return True

    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", side_effect=_sync):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert sorted(seen) == [("p-a", "Platform"), ("p-b", "Tools")]


def test_create_and_reconcile_see_the_same_re_pointed_target():
    """The same guarantee one level down, through the real sync_project_v3."""
    conf = _conf()
    targets = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "create_wi_v3",
                           side_effect=lambda *a: targets.append(("create", conf.azure_project))
                           or (0, 0, 0)), \
         mock.patch.object(core, "reconcile_project",
                           side_effect=lambda *a, **kw: targets.append(("close", conf.azure_project))
                           or (0, 0, 0, 0, 0)):
        _patches(conf, projects=[PROJECTS[0]])
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert targets == [("create", "Platform"), ("close", "Platform")]


def test_untagged_project_is_never_synced():
    conf = _conf()
    synced = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3",
                           side_effect=lambda p, *a: synced.append(p["uuid"]) or True):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert "p-c" not in synced


def test_excluded_project_never_reaches_routing():
    """MEND_EXCLUDETOKEN is applied by select_projects before routing, so an excluded project
    is simply not among the routed candidates."""
    conf = _conf(exclude="p-b")
    synced = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3",
                           side_effect=lambda p, *a: synced.append(p["uuid"]) or True):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert synced == ["p-a"]
    assert "1 of 2" in result           # p-b is out of the candidate set entirely


def test_run_is_not_fatal_when_every_outcome_is_a_deliberate_skip():
    """branch-filtered is "the normal state during rollout" per routing.py. A window where
    only other branches were scanned must not exit fatally."""
    conf = _conf()
    projects = [_project("p-dev", "api", _tags("Platform", branch="refs/heads/develop"))]
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True):
        _patches(conf, projects=projects, known={"Platform"})
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert core.sync_had_fatal_error() is False


def test_run_is_still_fatal_when_zero_routed_outcomes_are_genuine():
    """no-target/schema-fault are real misconfigurations, not deliberate skips, so a run made
    up entirely of those and zero routed targets must still trip the fatal path."""
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True):
        _patches(conf, projects=[_project("p-c", "untagged", {})], known={"Platform"})
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert core.sync_had_fatal_error() is True


def test_case_insensitive_tag_routes_to_the_canonical_azure_project_casing():
    # classify()'s known_projects membership check is deliberately exact-string, so the
    # case-insensitive normalisation has to happen in core.py before classify() runs. This
    # locks in both that the route is not lost (case mismatch alone must not produce
    # unknown-target) and that Azure API calls receive the real, canonically-cased name.
    conf = _conf()
    seen_azure_project = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3",
                           side_effect=lambda *a: seen_azure_project.append(conf.azure_project)
                           or True):
        _patches(conf, projects=[_project("p-lower", "api", _tags("platform"))],
                 known={"Platform"})
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert seen_azure_project == ["Platform"]   # canonical Azure casing, not the raw tag
    assert "1 of 1" in result
    assert core.synced_projects == [] or all(p[2] == "Platform" for p in core.synced_projects)


def test_aborts_when_the_azure_project_list_cannot_be_read():
    conf = _conf()
    with mock.patch.object(core, "sync_project_v3") as sync:
        _patches(conf, known=None)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    sync.assert_not_called()
    assert "aborted" in result.lower()


def test_a_failed_target_does_not_stop_the_others():
    # sorted(targets) visits "Platform" before "Tools"; get_exist_wi's side_effect fails
    # Platform first so this exercises failure isolation, not just "something failed".
    conf = _conf()
    synced = []
    with mock.patch.object(core, "get_exist_wi", side_effect=[None, []]), \
         mock.patch.object(core, "sync_project_v3",
                           side_effect=lambda p, *a: synced.append(
                               (p["uuid"], conf.azure_project)) or True):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    # Nothing is created OR closed for the target we could not read...
    assert synced == [("p-b", "Tools")]
    # ...and the failure is visible to main() via the fatal-error signal.
    assert core.sync_had_fatal_error() is True


def test_conf_azure_project_is_restored():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "sync_project_v3", return_value=True):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert conf.azure_project == "Bookkeeping"


def test_conf_azure_project_is_restored_even_when_a_target_raises():
    """try/finally, not a trailing assignment: a leaked target would send the NEXT run's
    closures into the wrong Azure project."""
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", side_effect=RuntimeError("boom")):
        _patches(conf)
        try:
            try:
                core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
            except RuntimeError:
                pass
        finally:
            mock.patch.stopall()
    assert conf.azure_project == "Bookkeeping"
