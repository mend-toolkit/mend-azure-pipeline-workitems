from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import Config, varenvs


def test_env_aliases_exist():
    assert varenvs.wsclosedstate.value == ("WS_CLOSEDSTATE", "MEND_CLOSEDSTATE")
    assert varenvs.wsreopenstate.value == ("WS_REOPENSTATE", "MEND_REOPENSTATE")


def test_config_carries_both_fields():
    for field in ("closed_state", "reopen_state"):
        assert field in Config.__dataclass_fields__


def test_unset_states_take_the_documented_defaults():
    """An unexpanded $(MEND_CLOSEDSTATE) must become the default, not empty -- an empty
    System.State would be rejected by Azure on every close."""
    for raw in ("", "$(MEND_CLOSEDSTATE)"):
        assert core.normalise_state(raw, "Closed") == "Closed"
        assert core.normalise_state(raw, "New") == "New"


def test_an_explicit_state_wins():
    assert core.normalise_state("Done", "Closed") == "Done"
    assert core.normalise_state("  To Do  ", "New") == "To Do"


TAGS = "ProductX/api; security vulnerability"
LIC_TAGS = "ProductX/api; license policy violation"


def _wi(title, wid, tags, state="Active"):
    return {title: {wid: {"tags": tags, "state": state}}}


def test_a_vulnerability_work_item_is_keyed_by_library():
    core.exist_wis = [_wi("log4j-core: 3 vulnerabilities (highest severity is 9.8)", 42, TAGS)]
    actual = core.actual_work_items("ProductX/api")
    assert actual[("vulnerability", "log4j-core")]["id"] == 42
    assert actual[("vulnerability", "log4j-core")]["state"] == "Active"


def test_a_license_work_item_is_keyed_by_library_too():
    core.exist_wis = [_wi("License Policy Violation detected in log4j-core", 43, LIC_TAGS)]
    actual = core.actual_work_items("ProductX/api")
    assert actual[("license", "log4j-core")]["id"] == 43


def test_a_closed_work_item_is_returned_with_its_state():
    """Without this, a closed item looks absent, gets re-created as a duplicate, and the
    original never reopens."""
    core.exist_wis = [_wi("log4j-core: 3 vulnerabilities (highest severity is 9.8)", 42,
                          TAGS, state="Closed")]
    actual = core.actual_work_items("ProductX/api")
    assert actual[("vulnerability", "log4j-core")]["state"] == "Closed"


def test_work_items_for_another_mend_project_are_excluded():
    core.exist_wis = [_wi("log4j-core: 3 vulnerabilities (highest severity is 9.8)", 42,
                          "ProductX/other; security vulnerability")]
    assert core.actual_work_items("ProductX/api") == {}


def test_a_title_matching_no_known_shape_is_ignored():
    """A hand-created work item that happens to carry the tag must not be adopted and closed."""
    core.exist_wis = [_wi("Investigate flaky deploy", 99, TAGS)]
    assert core.actual_work_items("ProductX/api") == {}


def test_both_kinds_for_one_library_coexist():
    core.exist_wis = [
        _wi("log4j-core: 3 vulnerabilities (highest severity is 9.8)", 42, TAGS),
        _wi("License Policy Violation detected in log4j-core", 43, LIC_TAGS),
    ]
    actual = core.actual_work_items("ProductX/api")
    assert actual[("vulnerability", "log4j-core")]["id"] == 42
    assert actual[("license", "log4j-core")]["id"] == 43


def test_a_malformed_entry_is_skipped_not_fatal():
    core.exist_wis = [{"bad": 12345},
                      _wi("log4j-core: 3 vulnerabilities (highest severity is 9.8)", 42, TAGS)]
    assert ("vulnerability", "log4j-core") in core.actual_work_items("ProductX/api")


def test_an_empty_cache_returns_empty():
    core.exist_wis = []
    assert core.actual_work_items("ProductX/api") == {}


def test_close_patches_only_the_state_field():
    """No description rewrite: the close path has no enrichment data and would blank the
    EPSS and reachability columns of a work item nobody is going to look at again."""
    seen = {}

    def fake(api_type, api, data=None, **kw):
        seen["type"], seen["api"], seen["data"] = api_type, api, data
        return {"id": 42}, 0

    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="P")), \
         mock.patch.object(core, "call_azure_api", fake):
        assert core.apply_close(42, "Closed") is True
    assert seen["type"] == "PATCH"
    assert "42" in seen["api"]
    assert [d["path"] for d in seen["data"]] == ["/fields/System.State"]
    assert seen["data"][0]["value"] == "Closed"


def test_reopen_patches_only_the_state_field():
    seen = {}

    def fake(api_type, api, data=None, **kw):
        seen["data"] = data
        return {"id": 42}, 0

    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="P")), \
         mock.patch.object(core, "call_azure_api", fake):
        assert core.apply_reopen(42, "New") is True
    assert [d["path"] for d in seen["data"]] == ["/fields/System.State"]
    assert seen["data"][0]["value"] == "New"


def test_an_invalid_transition_fails_one_item_without_raising():
    """Some processes disallow Closed -> New. That must cost one work item, not the run."""
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="P")), \
         mock.patch.object(core, "call_azure_api", return_value=({"message": "bad transition"}, 1)):
        assert core.apply_close(42, "Closed") is False


def test_a_transport_failure_also_returns_false_without_raising():
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="P")), \
         mock.patch.object(core, "call_azure_api", side_effect=Exception("boom")):
        assert core.apply_close(42, "Closed") is False


def test_a_duplicate_key_keeps_the_lowest_id_and_warns(caplog):
    """Two live work items for one (kind, library). The winner must be deterministic across
    runs, and the loser must never be closed -- we cannot tell which is canonical."""
    title = "log4j-core: 3 vulnerabilities (highest severity is 9.8)"
    core.exist_wis = [_wi(title, 77, TAGS), {title + " ": {42: {"tags": TAGS, "state": "New"}}}]
    with caplog.at_level("WARNING"):
        actual = core.actual_work_items("ProductX/api")
    assert actual[("vulnerability", "log4j-core")]["id"] == 42
    assert "77" in caplog.text and "42" in caplog.text


PROJECT = {"uuid": "p-1", "name": "api", "application_name": "ProductX"}


def _conf():
    return mock.patch.object(core, "conf", mock.MagicMock(azure_project="P",
                                                          closed_state="Closed",
                                                          reopen_state="New",
                                                          severity="high"))


def test_an_incomplete_read_skips_closures():
    """Closure safety. A truncated read looks exactly like a project whose findings were all
    remediated -- so on ok=False nothing may be closed."""
    closes = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, False)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert closes == [], "an incomplete read must never close a work item"
    assert stats[2] == 0


def test_an_incomplete_read_still_reopens():
    """A reopen cannot destroy anything, so the interlock does not gate it."""
    reopens = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired",
                           return_value=({("vulnerability", "log4j-core"): {}}, False)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Closed"}}), \
         mock.patch.object(core, "apply_reopen", lambda *a: reopens.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert reopens == [(42, "New")]
    assert stats[3] == 1


def test_a_complete_read_does_close():
    closes = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert closes == [(42, "Closed")]
    assert stats[2] == 1


def test_an_already_closed_item_produces_no_api_call_at_all():
    """The anti-oscillation rule: not a redundant close, NO call."""
    calls = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Closed"}}), \
         mock.patch.object(core, "apply_close", lambda *a: calls.append(a) or True), \
         mock.patch.object(core, "apply_reopen", lambda *a: calls.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert calls == []
    assert stats[4] == 1


def test_creates_and_updates_are_counted_but_never_executed():
    """CREATE/UPDATE stay on the creation path (create_wi_v3); this function must not call
    Azure for them."""
    calls = []
    desired = {("vulnerability", "log4j-core"): {}, ("license", "jackson"): {}}
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=(desired, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "call_azure_api", lambda *a, **k: calls.append(a) or ({}, 0)), \
         mock.patch.object(core, "create_wi_v3", lambda *a, **k: calls.append(a)):
        created, updated, closed, reopened, skipped = core.reconcile_project(PROJECT)
    assert calls == []
    assert (created, updated, closed, reopened, skipped) == (1, 1, 0, 0, 0)


def test_azure_is_read_before_mend():
    """exist_wis entries written after a POST/PATCH carry state "" -- the cache must be read
    while it still reflects Azure's pre-run state."""
    order = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired",
                           side_effect=lambda *a: order.append("mend") or ({}, True)), \
         mock.patch.object(core, "actual_work_items",
                           side_effect=lambda *a: order.append("azure") or {}):
        core.reconcile_project(PROJECT)
    assert order == ["azure", "mend"]


def test_a_failed_close_is_not_counted_as_closed():
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "apply_close", lambda *a: False):
        assert core.reconcile_project(PROJECT)[2] == 0


# MEND_SEVERITY decides creation AND closure -- and must decide them identically.
#
# These two tests replace the pair that asserted the closure read used a hard-coded floor of
# 0.0. That was right only while creation ran on 1.4, which applied no severity filter at all:
# closing a below-floor item 1.4 would re-create next run is the flapping bug. Creation now runs
# on 3.0 through create_wi_v3 at severity_floor(MEND_SEVERITY), so the opposite is true --
# closure reading at any OTHER floor is what flaps.

def test_the_closure_read_uses_the_configured_severity_floor():
    """Creation filters `desired` at severity_floor(MEND_SEVERITY); closure closes what is not
    in `desired`. A different floor here creates and closes the same item forever."""
    seen = {}
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired",
                           side_effect=lambda uuid, floor: seen.update(floor=floor) or ({}, True)), \
         mock.patch.object(core, "actual_work_items", return_value={}):
        core.reconcile_project(PROJECT)
    assert seen["floor"] == core.severity_floor("high") == 7.0


def test_an_explicit_floor_from_the_caller_wins():
    """sync_project_v3 passes the floor it created with, so the two halves cannot drift even if
    conf were re-pointed between them."""
    seen = {}
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired",
                           side_effect=lambda uuid, floor: seen.update(floor=floor) or ({}, True)), \
         mock.patch.object(core, "actual_work_items", return_value={}):
        core.reconcile_project(PROJECT, floor=4.0)
    assert seen["floor"] == 4.0


def test_a_below_floor_finding_is_closed_rather_than_left_to_flap():
    """End to end through the real fetch_v3_desired: with MEND_SEVERITY 9.0 a CVSS 2.1 finding
    earns no work item from create_wi_v3, so an existing one for it must be CLOSED. Leaving it
    open would contradict a creation path that will never write it again."""
    low = {"findingInfo": {"status": "ACTIVE"}, "component": {"name": "log4j-core"},
           "vulnerability": {"score": 2.1}}

    def _pages(api, *args, **kwargs):
        return ([low], True) if "findings/security" in api else ([], True)

    closes = []
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="P", closed_state="Closed",
                                                        reopen_state="New", severity="9.0")), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", side_effect=_pages), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert len(closes) == 1
    assert stats[2] == 1


# FINDING 2 -- the key-space interlock.

def _actual_two():
    return {("vulnerability", "log4j-core-2.14.1.jar"): {"id": 42, "state": "Active"},
            ("license", "jackson-databind-2.9.jar"): {"id": 43, "state": "Active"}}


def test_zero_key_overlap_skips_every_close_and_logs_the_two_key_spaces(caplog):
    """actual keys come from work item titles (1.4: library.filename), desired keys from 3.0
    component.name. Both sides full with NOT ONE key in common is a key-space mismatch, not a
    fully remediated project -- closing there would close every work item in the project."""
    desired = {("vulnerability", "log4j-core"): {}, ("license", "jackson-databind"): {}}
    closes = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=(desired, True)), \
         mock.patch.object(core, "actual_work_items", return_value=_actual_two()), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True), \
         caplog.at_level("ERROR"):
        stats = core.reconcile_project(PROJECT)
    assert closes == []
    assert stats[2] == 0
    assert "log4j-core" in caplog.text and "log4j-core-2.14.1.jar" in caplog.text


def test_an_empty_desired_still_closes_everything():
    """The legitimate case: nothing left in Mend means everything really was remediated, and
    those closes MUST still happen."""
    closes = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "actual_work_items", return_value=_actual_two()), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert sorted(closes) == [(42, "Closed"), (43, "Closed")]
    assert stats[2] == 2


def test_a_partial_overlap_closes_only_the_missing_one():
    """One shared key is enough to prove the key spaces agree; the genuinely absent item closes."""
    desired = {("vulnerability", "log4j-core-2.14.1.jar"): {}}
    closes = []
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=(desired, True)), \
         mock.patch.object(core, "actual_work_items", return_value=_actual_two()), \
         mock.patch.object(core, "apply_close", lambda *a: closes.append(a) or True):
        stats = core.reconcile_project(PROJECT)
    assert closes == [(43, "Closed")]
    assert stats[2] == 1


# --- per-CVE mode (MEND_DEPENDENCY=false) closure ---------------------------------------------
#
# Closure used to be dependency-mode only: classify_title could not decode
# "{CVE} ({Severity}) detected in {lib}", so actual_work_items never saw those items and
# reconciliation could neither close nor reopen them. These drive the WHOLE loop -- fetch, create,
# reconcile -- with only the two transports doubled, because the defect lived in the seam between
# the key `desired` is built on and the key a title decodes to, and a test that stubs either half
# cannot see it.

PER_CVE_TITLE = "CVE-2021-44228 (Critical) detected in log4j-core"
PER_CVE_KEY = ("vulnerability", "CVE-2021-44228|log4j-core")


def _per_cve_conf():
    return mock.MagicMock(azure_project="P", closed_state="Closed", reopen_state="New",
                          severity="high", dependency="false", azure_type="Task",
                          reachability="false", reponame="", routing="false",
                          description="Description", priority="false", azure_area="",
                          org_uuid="org-1", ws_url="saas.mend.io", proxy={})


def _security_finding(status="ACTIVE", cve="CVE-2021-44228", lib="log4j-core", severity="critical"):
    return {"component": {"name": lib, "version": "2.14.1", "references": {}},
            "vulnerability": {"name": cve, "score": 10.0, "severity": severity,
                              "description": "RCE", "references": []},
            "findingInfo": {"status": status}}


def _drive(findings, azure, conf):
    """One whole sync_project_v3 pass: 3.0 read -> create/update -> reconcile."""
    def pages(api, **kw):
        return (findings, True) if "findings/security" in api else ([], True)

    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "fetch_v3_pages", side_effect=pages), \
         mock.patch.object(core, "fetch_v3_licenses", return_value=({}, True)), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "synced_projects", []):
        core.sync_project_v3(PROJECT, 7.0, [], "Task")


def _calls(azure, api_type):
    return [c.kwargs for c in azure.call_args_list if c.kwargs.get("api_type") == api_type]


def test_a_suppressed_cve_closes_its_work_item_in_per_cve_mode():
    """The gap this closes. Run 1 creates the item; run 2 sees the finding IGNORED (suppressed
    in Mend) and must PATCH it Closed -- which needs classify_title to decode the per-CVE title
    into the very key `desired` was built on."""
    conf = _per_cve_conf()
    core.exist_wis = []
    created = mock.MagicMock(return_value=({"id": 101, "fields": {"System.State": "New"}}, 0))
    _drive([_security_finding()], created, conf)
    posted = [c for c in _calls(created, "POST") if "wit/workitems/$" in c["api"]]
    assert len(posted) == 1
    assert next(op["value"] for op in posted[0]["data"]
                if op["path"] == "/fields/System.Title") == PER_CVE_TITLE
    assert core.actual_work_items("ProductX/api")[PER_CVE_KEY]["id"] == 101

    # Run 2: the same finding, now suppressed in Mend. Nothing else changes.
    closed = mock.MagicMock(return_value=({"id": 101, "fields": {"System.State": "Closed", "System.WorkItemType": "Task"}}, 0))
    _drive([_security_finding(status="IGNORED")], closed, conf)
    patches = [c for c in _calls(closed, "PATCH") if c["api"] == "wit/workitems/101"]
    assert len(patches) == 1, "the suppressed CVE's work item was not closed"
    assert patches[0]["data"] == [{"op": "replace", "path": "/fields/System.State",
                                  "value": "Closed"}]


def test_a_returning_cve_reopens_the_same_work_item_not_a_new_one():
    """Reopen, not re-create: the operator's history, comments and links live on item 101."""
    conf = _per_cve_conf()
    # Azure holds the item this tool created and later closed -- the state a fresh get_exist_wi
    # sweep returns at the start of the next run.
    core.exist_wis = [_wi(PER_CVE_TITLE, 101, TAGS, state="Closed")]
    azure = mock.MagicMock(return_value=({"id": 101, "fields": {"System.State": "Closed", "System.WorkItemType": "Task"}}, 0))
    _drive([_security_finding()], azure, conf)

    assert [c for c in _calls(azure, "POST") if "wit/workitems/$" in c["api"]] == [], \
        "a returning CVE must reopen its work item, never create a second one"
    reopens = [c for c in _calls(azure, "PATCH")
               if c["data"] == [{"op": "replace", "path": "/fields/System.State",
                                 "value": "New"}]]
    assert len(reopens) == 1
    assert reopens[0]["api"] == "wit/workitems/101"


def test_a_rescored_cve_updates_its_work_item_rather_than_duplicating_it():
    """The severity word in the title moves on a rescore. Matching it exactly would create a
    second work item and strand the first open -- the defect this project exists to fix."""
    conf = _per_cve_conf()
    core.exist_wis = [_wi(PER_CVE_TITLE, 101, TAGS, state="Active")]
    azure = mock.MagicMock(return_value=({"id": 101, "fields": {"System.State": "Active", "System.WorkItemType": "Task"}}, 0))
    _drive([_security_finding(severity="high")], azure, conf)

    assert [c for c in _calls(azure, "POST") if "wit/workitems/$" in c["api"]] == []
    updates = [c for c in _calls(azure, "PATCH") if c["api"] == "wit/workitems/101"]
    assert len(updates) == 1
    assert next(op["value"] for op in updates[0]["data"]
                if op["path"] == "/fields/System.Title") == \
        "CVE-2021-44228 (High) detected in log4j-core"


def test_two_libraries_sharing_one_cve_hold_two_work_items_open():
    """Keying on the CVE alone would make these one key: the second work item would be absent
    from `desired` and closed on the very run that created it."""
    conf = _per_cve_conf()
    core.exist_wis = [_wi(PER_CVE_TITLE, 101, TAGS, state="Active"),
                      _wi("CVE-2021-44228 (Critical) detected in log4j-api", 102, TAGS,
                          state="Active")]
    azure = mock.MagicMock(return_value=({"id": 0, "fields": {"System.State": "Active", "System.WorkItemType": "Task"}}, 0))
    _drive([_security_finding(), _security_finding(lib="log4j-api")], azure, conf)

    closes = [c for c in _calls(azure, "PATCH")
              if c["data"] == [{"op": "replace", "path": "/fields/System.State",
                                "value": "Closed"}]]
    assert closes == [], "both CVEs are still ACTIVE in Mend; neither item may be closed"
    actual = core.actual_work_items("ProductX/api")
    assert actual[PER_CVE_KEY]["id"] == 101
    assert actual[("vulnerability", "CVE-2021-44228|log4j-api")]["id"] == 102
