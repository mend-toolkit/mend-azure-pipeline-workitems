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
