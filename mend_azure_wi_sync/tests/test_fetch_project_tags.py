import json
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import routing
from mend_azure_wi_sync import syncstate


def _conf():
    return mock.MagicMock(ws_user_key="uk", ws_org_token="ot")


# ---------------------------------------------------------------------------
# fetch_project_tags — the 1.4 getOrganizationProjectTags sweep, keyed by token directly.
# No 2.0 call and no (productName, projectName) join: the sweep run_sync already makes
# carries the routing tags against the same 1.4 token the rest of the run uses.
# ---------------------------------------------------------------------------

LIVE_ROWS = [{"name": "Test Workitems_master", "token": "tok-1", "tags": {
                 "azure-project": ["Test Pipeline Workitems"],
                 "azure-repo": ["Test Workitems"],
                 "azure-branch": ["refs/heads/master"],
                 "azure-wi-lastrun": ["2026-08-21 14:55:01"],
                 "CTX": ["ignored"]}},
             {"name": "AZ_IaC", "token": "tok-2", "tags": {"CTX": ["abc"]}}]


def test_routing_tags_come_from_the_1_4_sweep_keyed_by_token():
    """No 2.0 call, no (product, project) name join. The sweep the run already makes carries
    the routing tags against the same 1.4 token the rest of the run uses."""
    with mock.patch.object(core, "fetch_project_tag_state") as state, \
         mock.patch.object(core, "project_raw_tags",
                           syncstate.parse_raw_tags(LIVE_ROWS), create=True):
        state.return_value = {}
        tags = core.fetch_project_tags(["tok-1", "tok-2"])
    route = routing.parse_route(tags["tok-1"])
    assert route.azure_project == "Test Pipeline Workitems"
    assert route.repo == "Test Workitems"
    assert route.branch == "refs/heads/master"
    assert routing.parse_route(tags["tok-2"]).is_routable() is False


def test_parse_route_accepts_the_1_4_dict_of_lists():
    """The 2.0 shape was a list of {key, value}; 1.4 gives {key: [value, ...]}. Both must work
    while the two readers coexist, and the adapter must not silently drop a single-value list."""
    assert routing.parse_route({"azure-project": ["Payments"]}).azure_project == "Payments"
    assert routing.parse_route({"azure-project": "Payments"}).azure_project == "Payments"
    assert routing.parse_route([{"key": "azure-project", "value": "Payments"}]).azure_project == "Payments"


def test_a_project_absent_from_the_sweep_is_untagged_not_ambiguous():
    """The name-join produced a per-token None for an ambiguous (product, project) pair. Tokens
    cannot collide, so that signal is gone and an unknown token is simply untagged."""
    with mock.patch.object(core, "fetch_project_tag_state") as state, \
         mock.patch.object(core, "project_raw_tags", {}, create=True):
        state.return_value = {}
        tags = core.fetch_project_tags(["tok-missing"])
    assert tags == {"tok-missing": {}}
    assert None not in tags.values()


def test_an_unreadable_sweep_fails_the_whole_call():
    """Same all-or-nothing contract as before: a partial map would make a real project look
    untagged and route nothing, silently."""
    with mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "tag_sweep_ok", False, create=True):
        assert core.fetch_project_tags(["tok-1"]) is None


LIVE_SHAPE = json.dumps({"projectTags": [
    # Same fixture as test_syncstate_io.LIVE_SHAPE, copied rather than imported across test
    # modules (tests/ is not a package). Verbatim from the live org (2026-08-21).
    {"name": "AZ_IaC", "token": "tok-scan-only",
     "tags": {"CTX": ["99ef77b0"], "commitId": ["fe39bbda"],
              "repoFullName": ["DotNET-Demo/IaC@master"]}},
    {"name": "Test", "token": "tok-untagged", "tags": {}},
    {"name": "Test Workitems_master", "token": "tok-routed",
     "tags": {"azure-wi-project": ["Test Pipeline Workitems|Test Pipeline Workitems/Test Workitems_master"],
              "azure-branch": ["refs/heads/master"],
              "azure-project": ["Test Pipeline Workitems"],
              "azure-repo": ["Test Workitems"],
              "azure-wi-lastrun": ["2026-08-21 14:36:34"]}}]})


def test_fetch_project_tags_reads_the_real_sweep_end_to_end():
    """Every other test in this module patches core.project_raw_tags directly, so none of them
    would notice `project_raw_tags = parse_raw_tags(rows)` being deleted from
    fetch_project_tag_state -- they would stay green while every routed run in production died
    at "nothing routed" because project_raw_tags stayed {}. This drives a real HTTP-shaped body
    through fetch_project_tags with nothing patched but conf and call_ws_api -- one transport,
    one call. Confirmed to fail (empty route, no azure_project) if
    `project_raw_tags = parse_raw_tags(rows)` is commented out of fetch_project_tag_state."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=LIVE_SHAPE):
        tags = core.fetch_project_tags(["tok-routed"])
    route = routing.parse_route(tags["tok-routed"])
    assert route.azure_project == "Test Pipeline Workitems"
    assert route.repo == "Test Workitems"
    assert route.branch == "refs/heads/master"


def test_an_unreadable_sweep_fails_the_whole_call_via_the_real_failure_path():
    """test_an_unreadable_sweep_fails_the_whole_call above patches tag_sweep_ok directly, so it
    would stay green if core.py:468's `tag_sweep_ok = False` assignment were deleted. This drives
    the real unreadable-sweep branch of fetch_project_tag_state (call_ws_api returns a body with
    no "projectTags" key) and asserts on the resulting None, not on a patched flag."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5000}'):
        assert core.fetch_project_tags(["tok-1"]) is None


def test_a_structurally_unparseable_sweep_fails_the_whole_call_via_the_real_failure_path():
    """Same as above for the OTHER failure path (core.py:490): rows that are non-empty but that
    parse_tag_map/parse_raw_tags cannot structurally read (no "token"/"tags" keys) -- the shape
    guard's error branch, not a missing sweep. This is a genuinely new behaviour versus the
    pre-Task-4 code: previously an unparseable sweep only warned and let the run continue on the
    per-project clamp fallback, routing untouched. Now, because fetch_project_tags reads
    project_raw_tags from the very same sweep, a structurally-unparseable sweep also means no
    routing tags exist for anyone, and fetch_project_tags must fail the whole call rather than
    silently route nothing -- failing loudly beats routing nothing silently."""
    bad_shape = json.dumps({"projectTags": [{"unexpected": "shape"}]})
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value=bad_shape):
        assert core.fetch_project_tags(["tok-1"]) is None


def test_a_failed_tag_write_does_not_break_routing():
    """tag_state_available is shared with every tag WRITE (save/removeProjectTag), not just the
    sweep. A single failed saveProjectTag later in a run must not make fetch_project_tags act as
    though the sweep itself failed and abort routing for the rest of the run."""
    with mock.patch.object(core, "fetch_project_tag_state", return_value={}), \
         mock.patch.object(core, "tag_state_available", False, create=True), \
         mock.patch.object(core, "tag_sweep_ok", True, create=True), \
         mock.patch.object(core, "project_raw_tags", {}, create=True):
        assert core.fetch_project_tags(["tok-1"]) == {"tok-1": {}}
