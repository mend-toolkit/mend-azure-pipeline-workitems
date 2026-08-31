from mend_azure_wi_sync import reconcile

VULN = ("vulnerability", "log4j-core")
LIC = ("license", "log4j-core")


def _entry(kind="vulnerability", lib="log4j-core"):
    return {"library": lib, "kind": kind, "findings": [{"name": "CVE-1"}]}


def _by_action(actions):
    return {a["action"]: a for a in actions}


def test_a_finding_with_no_work_item_is_created():
    actions = reconcile.plan_actions({VULN: _entry()}, {}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.CREATE]
    assert actions[0]["key"] == VULN


def test_a_finding_with_an_open_work_item_is_updated():
    actions = reconcile.plan_actions({VULN: _entry()}, {VULN: {"id": 42, "state": "Active"}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.UPDATE]
    assert actions[0]["id"] == 42


def test_a_vanished_finding_closes_its_open_work_item():
    """The defect this whole design exists to fix: the library was removed or the
    vulnerability was suppressed, so it is absent from desired."""
    actions = reconcile.plan_actions({}, {VULN: {"id": 42, "state": "Active"}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.CLOSE]
    assert actions[0]["id"] == 42


def test_an_already_closed_work_item_is_SKIPPED_not_closed_again():
    """LOAD-BEARING. If an Azure process rule reactivates a Closed item on any PATCH, closing
    it again would reopen it, and the item would oscillate forever. Making no call at all is
    correct whether or not that rule exists."""
    actions = reconcile.plan_actions({}, {VULN: {"id": 42, "state": "Closed"}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.SKIP]


def test_a_returning_finding_reopens_the_same_work_item():
    """Library removed, then added back: the SAME item reopens, history intact."""
    actions = reconcile.plan_actions({VULN: _entry()}, {VULN: {"id": 42, "state": "Closed"}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.REOPEN]
    assert actions[0]["id"] == 42


def test_the_closed_state_comparison_is_case_insensitive():
    """Azure returns state names as configured; a case difference must not turn a skip
    into a close-and-reopen loop."""
    actions = reconcile.plan_actions({}, {VULN: {"id": 42, "state": "closed"}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.SKIP]


def test_a_custom_closed_state_is_honoured():
    actions = reconcile.plan_actions({}, {VULN: {"id": 42, "state": "Done"}}, "Done")
    assert [a["action"] for a in actions] == [reconcile.SKIP]


def test_vulnerability_and_license_items_for_one_library_are_independent():
    """They are two work items with different titles; one closing must not touch the other."""
    actions = reconcile.plan_actions(
        {VULN: _entry()},
        {VULN: {"id": 42, "state": "Active"}, LIC: {"id": 43, "state": "Active"}},
        "Closed")
    by = _by_action(actions)
    assert by[reconcile.UPDATE]["id"] == 42
    assert by[reconcile.CLOSE]["id"] == 43


def test_an_empty_project_produces_no_actions():
    assert reconcile.plan_actions({}, {}, "Closed") == []


def test_every_desired_and_actual_key_appears_exactly_once():
    """No key may be both created and closed -- that would fight itself every run."""
    desired = {VULN: _entry(), ("vulnerability", "jackson"): _entry(lib="jackson")}
    actual = {VULN: {"id": 1, "state": "Active"}, LIC: {"id": 2, "state": "Closed"}}
    actions = reconcile.plan_actions(desired, actual, "Closed")
    keys = [a["key"] for a in actions]
    assert len(keys) == len(set(keys))
    assert set(keys) == set(desired) | set(actual)


def test_a_missing_state_is_treated_as_open_not_closed():
    """Unknown state must not be read as closed -- that would silently stop closing items."""
    actions = reconcile.plan_actions({}, {VULN: {"id": 42}}, "Closed")
    assert [a["action"] for a in actions] == [reconcile.CLOSE]


def test_garbage_inputs_return_no_actions_rather_than_raising():
    assert reconcile.plan_actions(None, None, "Closed") == []
