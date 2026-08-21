from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate

# The reverse sync used to be scoped per Azure project (visiting every project the
# forward sync routed to, via the now-removed `routed_targets` list, and closing each
# target's window with a single project-wide Lastrun property), then per Mend project but
# gated on `synced_projects` -- this run's forward successes.
#
# That gating was itself a regression (spec 5.6.1): it meant a dormant or archived repo,
# never touched by this run's forward sync, was never revisited, and a work item closed
# there never reached Mend. update_wi_in_thread now walks `core.reverse_targets(state)`,
# which reads every project the read-once Mend project tag map has a stored
# `azure-wi-project` ("{azure_project}|{product}/{project}") address for -- independent of
# `synced_projects`, which now only supplies the address for `save_project_addr` (core.py)
# to persist. These tests are rewritten against that contract; the old per-Azure-project /
# per-target Lastrun assertions remain deliberately obsolete (spec decision 6).


def _conf(**kw):
    base = dict(azure_project="Bookkeeping", utc_delta=0,
                wsproducttoken="", wsprojecttoken="", wsexcludetoken="")
    base.update(kw)
    return mock.MagicMock(**base)


def test_reverse_sync_visits_every_project_with_a_stored_address():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append((tok, tag)) or "ok"):
        core.update_wi_in_thread()
    assert seen == [("tok-1", "Prod/Platform"), ("tok-2", "Prod/Tools")]


def test_reverse_sync_points_conf_azure_project_at_each_targets_own_azure_project():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen_azure_project = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen_azure_project.append(
                               core.conf.azure_project) or "ok"):
        core.update_wi_in_thread()
    assert seen_azure_project == ["Platform", "Tools"]


def test_reverse_sync_restores_the_original_project():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    conf = _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok"):
        core.update_wi_in_thread()
    assert conf.azure_project == "Bookkeeping"


def test_reverse_sync_is_skipped_when_no_project_has_a_stored_address():
    core.project_tag_state = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project") as inner:
        result = core.update_wi_in_thread()
    inner.assert_not_called()
    assert "skipped" in result.lower()


def test_reverse_sync_skips_a_target_with_a_malformed_stored_address():
    """An empty Azure project half, an empty tag half, or a tag half with a leading or
    trailing "/" means the stored address is unusable. Querying with it would match
    nothing, or (worse) everything -- so that target must be skipped rather than passed to
    update_wi_for_project, and never guessed at (e.g. falling back to conf.azure_project)."""
    core.project_tag_state = {
        "tok-bad-1": {"project": "|Prod/Proj"},
        "tok-bad-2": {"project": "Platform|"},
        "tok-bad-3": {"project": "Platform|/Proj"},
        "tok-bad-4": {"project": "Platform|Prod/"},
        "tok-good": {"project": "Platform|Prod/Proj"},
    }
    seen = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-good"]


def test_the_per_target_results_are_joined_into_one_report():
    """update_wi_for_project owns advancing its own project's revsync tag on success or
    withholding it on failure (see test_reverse_sync_state.py); update_wi_in_thread's
    job is just to call it once per addressed Mend project and report each result -- it no
    longer gates one target's watermark write on another's outcome, because there is no
    longer a single shared watermark to gate."""
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
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
    core.project_tag_state = {"tok-fail": {"project": "AzureFail|Prod/Fail"},
                              "tok-ok": {"project": "AzureOk|Prod/Ok"}}

    def fake_call_azure_api(*a, **kw):
        if kw.get("project") == "AzureFail":
            return {"message": "boom"}, 2
        return {"workItems": []}, 0

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", side_effect=fake_call_azure_api), \
         mock.patch.object(core, "save_project_tag", return_value=True) as save:
        core.update_wi_in_thread()

    assert save.call_count == 1
    assert save.call_args.args[0] == "tok-ok"


def test_the_non_routed_path_persists_an_address_the_reverse_sync_can_later_use():
    """Guards the new wiring end to end: create_wi's unconditional append to
    `synced_projects` -> `save_project_addr` (core.py) writing TAG_PROJECT -> a later run's
    update_wi_in_thread reading that address back out of the tag map and visiting it,
    without any dependence on `synced_projects` at that point. create_wi is mocked here --
    its own append contract, decoupled from item_failed by this task, is covered directly
    against the real function by test_create_wi_verdict.py -- but its side_effect performs
    that same append, so this test exercises the real
    run_sync -> synced_projects -> save_project_addr -> tag map -> update_wi_in_thread
    wiring end to end."""
    conf = mock.MagicMock(routing="false", wsproducttoken="", wsprojecttoken="",
                          wsexcludetoken="", azure_project="Bookkeeping", utc_delta=0)

    def fake_create_wi(token, *a, **kw):
        core.synced_projects.append((token, f"Prod/{token}", conf.azure_project))
        return syncstate.VERDICT_OK, "done"

    saved_tags = {}

    def fake_save_project_tag(token, key, value):
        saved_tags.setdefault(token, {})[key] = value
        return True

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=["tok-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "save_project_tag", side_effect=fake_save_project_tag), \
         mock.patch.object(core, "create_wi", side_effect=fake_create_wi):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

    # save_project_addr found tok-1 in synced_projects and, since the (mocked-empty) tag
    # map held no address yet, persisted one.
    assert saved_tags["tok-1"][syncstate.TAG_PROJECT] == "Bookkeeping|Prod/tok-1"

    # A later run reads that address back out of the tag map -- no synced_projects
    # involved -- and visits the project.
    core.project_tag_state = {"tok-1": {"project": saved_tags["tok-1"][syncstate.TAG_PROJECT]}}
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "update_wi_for_project", return_value="ok") as inner:
        result = core.update_wi_in_thread()
    inner.assert_called_once()
    assert "skipped" not in result.lower()


def test_a_project_addressed_for_the_first_time_is_visited_in_the_same_run():
    """Closes the day-one gap (fix round 1, item 2): before this fix, save_project_addr
    wrote TAG_PROJECT to Mend but never updated the in-memory tag map
    fetch_project_tag_state() memoises, so the SAME run's update_wi_in_thread (which reads
    that same memoised map) would still see no address for a project addressed for the
    first time this run, and skip it -- self-healing only on the following run. Exercises
    the real run_sync -> save_project_addr -> update_wi_in_thread sequence exactly as
    azure_wi_sync.py's main() calls them, back to back in one process, with no reset of
    core.project_tag_state in between."""
    conf = mock.MagicMock(routing="false", wsproducttoken="", wsprojecttoken="",
                          wsexcludetoken="", azure_project="Bookkeeping", utc_delta=0)
    core.project_tag_state = {}   # no stored address yet -- this project's first-ever run

    def fake_create_wi(token, *a, **kw):
        core.synced_projects.append((token, f"Prod/{token}", conf.azure_project))
        return syncstate.VERDICT_OK, "done"

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "get_prj_list_modified", return_value=["tok-1"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "save_project_tag", return_value=True), \
         mock.patch.object(core, "create_wi", side_effect=fake_create_wi):
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")

        # No reset of core.project_tag_state here: same run, same process.
        with mock.patch.object(core, "update_wi_for_project", return_value="ok") as inner:
            result = core.update_wi_in_thread()

    inner.assert_called_once_with("tok-1", "Prod/tok-1", mock.ANY)
    assert "skipped" not in result.lower()


def test_save_project_addr_is_a_noop_when_the_stored_address_already_matches():
    """The steady-state guarantee (fix round 1, item 1). Once azure-wi-project already
    holds the address create_wi resolved this run, saving it again must not happen -- at
    ~400 projects an unconditional write costs a saveProjectTag call every run for every
    project, and it is unverified whether a repeated save on one key yields one row or a
    duplicate. See the report's load-bearing proof: dropping the comparison leaves this
    test (and only this test) failing."""
    core.synced_projects = [("tok-1", "Prod/Proj", "Platform")]
    state = {"tok-1": {"project": "Platform|Prod/Proj"}}
    with mock.patch.object(core, "conf", _conf(azure_project="Platform")), \
         mock.patch.object(core, "save_project_tag", return_value=True) as save:
        core.save_project_addr("tok-1", state)
    save.assert_not_called()


def test_save_project_addr_writes_when_the_stored_address_differs():
    core.synced_projects = [("tok-1", "Prod/Proj", "Platform")]
    state = {"tok-1": {"project": "OldProject|Prod/Proj"}}
    with mock.patch.object(core, "conf", _conf(azure_project="Platform")), \
         mock.patch.object(core, "save_project_tag", return_value=True) as save:
        core.save_project_addr("tok-1", state)
    save.assert_called_once_with("tok-1", syncstate.TAG_PROJECT, "Platform|Prod/Proj")
    assert state["tok-1"]["project"] == "Platform|Prod/Proj"


def test_reverse_targets_strips_whitespace_from_a_padded_stored_address():
    """Fix round 1, item 3: a padded address ("Platform| Prod/Proj ") must not carry that
    padding into the WIQL tag clause, where it would match nothing. A half that is only
    whitespace ("   ") must be treated as malformed, not pass the emptiness check because
    it is technically non-empty before stripping."""
    state = {"tok-1": {"project": "Platform| Prod/Proj "},
             "tok-2": {"project": "Platform|   "}}
    assert core.reverse_targets(state) == [("tok-1", "Platform", "Prod/Proj")]


# --- Reverse sync respects MEND_PRODUCTTOKEN / MEND_PROJECTTOKEN / MEND_EXCLUDETOKEN ---
#
# An operator scoping a run to one project was still paying a WIQL query plus a work-item
# hydration for every project the org has ever tagged, because update_wi_in_thread walked
# the whole tag map with no regard for the same scope the forward sync honours. These tests
# mirror run_sync_routed's narrowing contract (core.py:1747-1765) for the reverse path.


def test_reverse_sync_is_narrowed_by_wsprojecttoken():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen = []
    with mock.patch.object(core, "conf", _conf(wsprojecttoken="tok-1")), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-1"]


def test_reverse_sync_is_narrowed_by_wsproducttoken():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen = []
    with mock.patch.object(core, "conf", _conf(wsproducttoken="prd-1")), \
         mock.patch.object(core, "expand_product_tokens", return_value=["tok-1"]), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-1"]


def test_reverse_sync_always_subtracts_wsexcludetoken():
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen = []
    with mock.patch.object(core, "conf", _conf(wsexcludetoken="tok-2")), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-1"]


def test_reverse_sync_with_empty_config_narrows_nothing():
    """Spec 5.6.1's dormant-repo guarantee: absent MEND_PRODUCTTOKEN/MEND_PROJECTTOKEN,
    every tagged project must still be visited, or a quiet/dormant repo whose work items
    get closed would never be pushed back to Mend."""
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"},
                              "tok-2": {"project": "Tools|Prod/Tools"}}
    seen = []
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda tok, tag, todate: seen.append(tok) or "ok"):
        core.update_wi_in_thread()
    assert seen == ["tok-1", "tok-2"]


def test_reverse_sync_aborts_rather_than_widen_scope_on_a_failed_expansion():
    """expand_product_tokens returning None must never be treated as 'no scope' -- that
    would silently visit every tagged project, which is the exact bug this filtering
    exists to fix."""
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"}}
    with mock.patch.object(core, "conf", _conf(wsproducttoken="prd-1")), \
         mock.patch.object(core, "expand_product_tokens", return_value=None), \
         mock.patch.object(core, "update_wi_for_project") as inner:
        before = core.global_errors
        result = core.update_wi_in_thread()
    inner.assert_not_called()
    assert core.global_errors == before + 1
    assert core.sync_had_fatal_error() is True
    assert "abort" in result.lower()


def test_reverse_sync_scope_expansion_is_memoized():
    """expand_product_tokens costs one Mend call per product token and is already called
    once per run by whichever forward path ran; the reverse path must reuse that result
    rather than paying for it again."""
    core.project_tag_state = {"tok-1": {"project": "Platform|Prod/Platform"}}
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="k", ws_org_token="o")), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"projects": [{"projectToken": "tok-1"}]}') as api:
        first = core.expand_product_tokens("prd-memo-test")
        second = core.expand_product_tokens("prd-memo-test")
    assert first == ["tok-1"]
    assert second == ["tok-1"]
    assert api.call_count == 1


def test_a_failed_expansion_is_not_memoized():
    """Only a successful expansion may be cached -- caching a failure would paper over a
    transient Mend outage as a permanent empty scope."""
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="k", ws_org_token="o")), \
         mock.patch.object(core, "call_ws_api", side_effect=["", '{"projects": []}']) as api:
        first = core.expand_product_tokens("prd-memo-fail")
        second = core.expand_product_tokens("prd-memo-fail")
    assert first is None
    assert second == []
    assert api.call_count == 2


# --- routing narrows the reverse sync too (reported live 2026-08-21) ---
# Under MEND_ROUTING the token lists are not the selector, routing tags are. Scoping the
# reverse sync by MEND_PRODUCTTOKEN/PROJECTTOKEN therefore narrows nothing in a routed run,
# so enabling routing on an org where one project carries tags still cost a WIQL query plus
# a work-item hydration for every project that had ever stored an address.

def _routed_state():
    return {"tok-tagged": {"project": "Platform|Prod/Tagged"},
            "tok-untagged": {"project": "Tools|Prod/Untagged"},
            "tok-otherbranch": {"project": "Extra|Prod/Other"}}


def _raw_tags():
    return {"tok-tagged": {"azure-project": ["Platform"], "azure-repo": ["Tagged"],
                           "azure-branch": ["refs/heads/main"]},
            # carries a stored address from an earlier run but no routing tags any more
            "tok-untagged": {"CTX": ["abc"], "commitId": ["def"]},
            "tok-otherbranch": {"azure-project": ["Extra"], "azure-repo": ["Other"],
                                "azure-branch": ["refs/heads/feature/x"]}}


def _visited(**conf_kw):
    seen = []
    base = dict(routing="true", branches="main", wsproducttoken="", wsprojecttoken="",
                wsexcludetoken="", azure_project="Bookkeeping", utc_delta=0)
    base.update(conf_kw)
    with mock.patch.object(core, "conf", mock.MagicMock(**base)), \
         mock.patch.object(core, "fetch_project_tag_state", return_value=_routed_state()), \
         mock.patch.object(core, "project_raw_tags", _raw_tags(), create=True), \
         mock.patch.object(core, "update_wi_for_project",
                           side_effect=lambda t, *a, **k: seen.append(t) or "ok"):
        core.update_wi_in_thread()
    return sorted(seen)


def test_routing_reverse_sync_skips_a_project_whose_routing_tags_are_gone():
    """The reported symptom: routing on, one project tagged, yet every project that had ever
    stored an address was still visited. A stored address is where work items LIVE; the
    routing tags are what says this project is still ours to sync."""
    assert _visited() == ["tok-tagged"]


def test_routing_reverse_sync_respects_mend_branches():
    """A branch-filtered project is deliberately out of scope on the forward side, so paying
    a WIQL for it on the reverse side is the same wasted work in the other direction."""
    assert _visited(branches="feature/*") == ["tok-otherbranch"]
    assert _visited(branches="main,feature/*") == ["tok-otherbranch", "tok-tagged"]


def test_routing_off_still_uses_the_token_lists_not_the_routing_tags():
    """With routing off, an untagged project is a perfectly normal target -- selection comes
    from the token lists, and narrowing by routing tags there would silently drop projects."""
    assert _visited(routing="false") == ["tok-otherbranch", "tok-tagged", "tok-untagged"]


def test_routing_on_with_no_routable_project_skips_cleanly():
    assert _visited(branches="nothing-matches-this") == []
