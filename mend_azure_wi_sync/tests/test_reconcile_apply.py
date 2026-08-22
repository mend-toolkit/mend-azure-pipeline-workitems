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
                                                          reopen_state="New"))


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
        stats = core.reconcile_project(PROJECT, 7.0)
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
        stats = core.reconcile_project(PROJECT, 7.0)
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
        stats = core.reconcile_project(PROJECT, 7.0)
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
        stats = core.reconcile_project(PROJECT, 7.0)
    assert calls == []
    assert stats[4] == 1


def test_creates_and_updates_are_counted_but_never_executed():
    """CREATE/UPDATE stay on the 1.4 create_wi path; this function must not call Azure for
    them."""
    calls = []
    desired = {("vulnerability", "log4j-core"): {}, ("license", "jackson"): {}}
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=(desired, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "call_azure_api", lambda *a, **k: calls.append(a) or ({}, 0)), \
         mock.patch.object(core, "create_wi", lambda *a, **k: calls.append(a)):
        created, updated, closed, reopened, skipped = core.reconcile_project(PROJECT, 7.0)
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
        core.reconcile_project(PROJECT, 7.0)
    assert order == ["azure", "mend"]


def test_a_failed_close_is_not_counted_as_closed():
    with _conf(), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "actual_work_items",
                           return_value={("vulnerability", "log4j-core"): {"id": 42,
                                                                           "state": "Active"}}), \
         mock.patch.object(core, "apply_close", lambda *a: False):
        assert core.reconcile_project(PROJECT, 7.0)[2] == 0
