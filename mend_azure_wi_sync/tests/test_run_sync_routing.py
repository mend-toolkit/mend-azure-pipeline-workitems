from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate


def _conf(routing="true", exclude="", product="", project=""):
    return mock.MagicMock(routing=routing, branches="main,master", azure_project="Bookkeeping",
                          reponame="", wsproducttoken=product, wsprojecttoken=project,
                          wsexcludetoken=exclude)


TAGS = {
    "tok-a": [{"key": "azure-project", "value": "Platform"},
              {"key": "azure-repo", "value": "api"},
              {"key": "azure-branch", "value": "refs/heads/main"}],
    "tok-b": [{"key": "azure-project", "value": "Tools"},
              {"key": "azure-repo", "value": "cli"},
              {"key": "azure-branch", "value": "refs/heads/main"}],
    "tok-c": [],
}


def _patches(conf, known={"Platform", "Tools"}):
    """Start the common patches; every test using this must call mock.patch.stopall()."""
    for p in (mock.patch.object(core, "conf", conf),
              mock.patch.object(core, "get_prj_list_modified", return_value=list(TAGS)),
              mock.patch.object(core, "fetch_project_tags", return_value=TAGS),
              mock.patch.object(core, "list_azure_projects", return_value=known)):
        p.start()


def test_routing_off_does_not_call_the_tag_api():
    with mock.patch.object(core, "conf", _conf(routing="false")), \
         mock.patch.object(core, "get_prj_list_modified", return_value=["tok-a"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")), \
         mock.patch.object(core, "fetch_project_tags") as tags:
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    tags.assert_not_called()


def test_routing_on_syncs_each_azure_target_once():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]) as exist, \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert exist.call_count == 2          # once per Azure project, not once per Mend project
    assert "2 of 3" in result


def test_excluded_token_is_never_synced_and_is_reported_distinctly():
    conf = _conf(exclude="tok-b")
    created = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi",
                           side_effect=lambda t, *a, **k: created.append(t) or (syncstate.VERDICT_OK, "done")):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert "tok-b" not in created
    assert "scope-excluded" in result


def test_untagged_project_is_never_synced():
    conf = _conf()
    created = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi",
                           side_effect=lambda t, *a, **k: created.append(t) or (syncstate.VERDICT_OK, "done")):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert "tok-c" not in created


def test_run_is_not_fatal_when_every_outcome_is_a_deliberate_skip():
    """CRITICAL 2: scope-excluded, out-of-scope and branch-filtered are deliberate
    outcomes — branch-filtered is "the normal state during rollout" per routing.py's own
    comment. A pilot window where only other projects changed must not exit fatally just
    because nothing routed here."""
    conf = _conf(exclude="tok-excluded")
    tags = {
        "tok-excluded": [{"key": "azure-project", "value": "Platform"},
                         {"key": "azure-repo", "value": "api"},
                         {"key": "azure-branch", "value": "refs/heads/main"}],
        "tok-branch-filtered": [{"key": "azure-project", "value": "Platform"},
                                {"key": "azure-repo", "value": "cli"},
                                {"key": "azure-branch", "value": "refs/heads/develop"}],
    }
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=list(tags)), \
         mock.patch.object(core, "fetch_project_tags", return_value=tags), \
         mock.patch.object(core, "list_azure_projects", return_value={"Platform"}), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")):
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert core.sync_had_fatal_error() is False


def test_run_is_still_fatal_when_zero_routed_outcomes_are_genuine():
    """CRITICAL 2, other half: no-target/schema-fault are real misconfigurations, not
    deliberate skips, so a run made up entirely of those and zero routed targets must
    still trip the fatal path."""
    conf = _conf()
    tags = {"tok-untagged": []}
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=list(tags)), \
         mock.patch.object(core, "fetch_project_tags", return_value=tags), \
         mock.patch.object(core, "list_azure_projects", return_value={"Platform"}), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")):
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert core.sync_had_fatal_error() is True


def test_collided_token_reaches_a_loud_outcome_not_the_quiet_no_target_bucket():
    # fetch_project_tags returns a per-token None (not []) when the (product, project)
    # name pair collided in /entities and the join is ambiguous. That must classify as
    # the loud "unknown-target" outcome, never fall into the quiet "no-target" bucket
    # that an empty/absent route would otherwise produce via parse_route(None or []).
    conf = _conf()
    tags = dict(TAGS)
    tags["tok-collided"] = None
    created = []
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=list(tags)), \
         mock.patch.object(core, "fetch_project_tags", return_value=tags), \
         mock.patch.object(core, "list_azure_projects", return_value={"Platform", "Tools"}), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi",
                           side_effect=lambda t, *a, **k: created.append(t) or (syncstate.VERDICT_OK, "done")):
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert "tok-collided" not in created
    # tok-c is the genuinely-untagged one; tok-collided must be counted separately as
    # unknown-target, not lumped into the same no-target bucket as tok-c.
    assert "no-target: 1" in result
    assert "unknown-target: 1" in result


def test_case_insensitive_tag_routes_to_the_canonical_azure_project_casing():
    # classify()'s known_projects membership check is deliberately exact-string, so the
    # case-insensitive normalisation has to happen in core.py before classify() runs. This
    # locks in both that the route is not lost (case mismatch alone must not produce
    # unknown-target) and that Azure API calls receive the real, canonically-cased name
    # rather than whatever casing happened to be on the tag.
    conf = _conf()
    tags = {"tok-lower": [{"key": "azure-project", "value": "platform"},
                          {"key": "azure-repo", "value": "api"},
                          {"key": "azure-branch", "value": "refs/heads/main"}]}
    seen_azure_project = []

    def fake_create_wi(token, *a, **kw):
        # Stands in for create_wi, which is the only place that appends to
        # synced_projects (core.py). Recording conf.azure_project here mirrors that
        # real behaviour so this test can still assert on the canonical casing that
        # flows through to what the reverse sync will later query against.
        seen_azure_project.append(conf.azure_project)
        core.synced_projects.append((token, f"Product/{token}", conf.azure_project))
        return syncstate.VERDICT_OK, "done"

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=list(tags)), \
         mock.patch.object(core, "fetch_project_tags", return_value=tags), \
         mock.patch.object(core, "list_azure_projects", return_value={"Platform"}), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         mock.patch.object(core, "create_wi", side_effect=fake_create_wi):
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert seen_azure_project == ["Platform"]   # canonical Azure casing, not the raw "platform" tag
    assert "1 of 1" in result
    # synced_projects (create_wi's contract) carries the canonical Azure casing that the
    # reverse sync scopes its WIQL to — this supersedes the old routed_targets list.
    assert any(p[2] == "Platform" for p in core.synced_projects)


def test_routing_wires_prepare_enrichment_with_the_routed_token_list():
    """IMPORTANT 3: prepare_enrichment must actually be called from the routed path, or
    every enabled customer silently gets three columns of '-' with all tests green."""
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")), \
         mock.patch.object(core, "prepare_enrichment") as prepare:
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    prepare.assert_called_once()
    (called_tokens,), _ = prepare.call_args
    # tok-c is untagged and never reaches a routing target; tok-a/tok-b do.
    assert set(called_tokens) == {"tok-a", "tok-b"}


def test_aborts_when_the_project_list_cannot_be_read():
    conf = _conf()
    with mock.patch.object(core, "create_wi") as create:
        _patches(conf, known=None)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    create.assert_not_called()
    assert "aborted" in result.lower()


def test_a_failed_target_does_not_stop_the_others():
    # sorted(targets) visits "Platform" before "Tools"; get_exist_wi's side_effect fails
    # Platform first so this exercises the failure-isolation and Lastrun-safety paths, not
    # just "some target failed, some target didn't".
    conf = _conf()

    def fake_create_wi(token, *a, **kw):
        # Stands in for create_wi, which is the only place that appends to
        # synced_projects (core.py) — the list the reverse sync now walks instead of
        # the removed routed_targets.
        core.synced_projects.append((token, f"Product/{token}", conf.azure_project))
        return syncstate.VERDICT_OK, "done"

    with mock.patch.object(core, "get_exist_wi", side_effect=[None, []]), \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         mock.patch.object(core, "create_wi", side_effect=fake_create_wi) as create:
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert create.call_count == 1
    # The failure must be visible to main() via the fatal-error signal...
    assert core.sync_had_fatal_error() is True
    # ...and the failed target's Azure project must never appear among synced_projects:
    # its Mend project window must stay open for retry, and the reverse sync (which now
    # walks synced_projects instead of the removed routed_targets) must not visit it.
    tracked_azure_projects = {p[2] for p in core.synced_projects}
    assert "Platform" not in tracked_azure_projects
    assert "Tools" in tracked_azure_projects


def test_conf_azure_project_is_restored():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value=(syncstate.VERDICT_OK, "done")):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert conf.azure_project == "Bookkeeping"


def test_expand_product_tokens_survives_a_non_json_response():
    """The original raised JSONDecodeError here and killed the whole run."""
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="k", ws_org_token="o")), \
         mock.patch.object(core, "call_ws_api", return_value=""):
        assert core.expand_product_tokens("prd-1") is None   # None, not [] — see the scope guard
