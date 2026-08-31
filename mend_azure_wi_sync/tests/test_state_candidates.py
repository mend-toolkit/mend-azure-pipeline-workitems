"""Closing and reopening work items across Azure DevOps's four out-of-box processes.

Live failure that prompted this (work item 8118, two boards on different processes):

    Could not close work item 8118 to state 'Closed': {"[call_azure_api:547] Status code: 400 -
    The field 'State' contains the value 'Closed' that is not in the list of supported values"}

MEND_CLOSEDSTATE was a single global string applied to every project, and 'Closed' is not a legal
state in every process. The four out-of-box processes need only TWO closed values between them:

    | Process | States                                  | Closed   | Reopen    |
    | Agile   | New / Active / Resolved / Closed         | Closed   | New       |
    | CMMI    | Proposed / Active / Resolved / Closed    | Closed   | Proposed  |
    | Scrum   | New / Approved / Committed / Done        | Done     | New       |
    | Scrum   | To Do / In Progress / Done  (Task)       | Done     | To Do     |
    | Basic   | To Do / Doing / Done                     | Done     | To Do     |

So no API discovery is needed: try the known defaults, and let an operator whose DERIVED process
renamed the state set MEND_CLOSEDSTATE / MEND_REOPENSTATE explicitly. An explicit value is used
ALONE -- never second-guessed, never followed by a fallback attempt.
"""

from unittest import mock

from mend_azure_wi_sync import core


UNSUPPORTED = {"[call_azure_api:547] Status code: 400 - The field 'State' contains the value "
               "'Closed' that is not in the list of supported values"}
# A 400 that is NOT about the state name: the value was legal, the TRANSITION was refused. Retrying
# a different state here would issue a second bad write against a work item that is fine.
TRANSITION_REFUSED = {"[call_azure_api:547] Status code: 400 - The work item state transition is "
                      "not valid: New to Closed"}


def _conf(**overrides):
    values = dict(azure_project="TestProj", azure_type="Task", closed_state="", reopen_state="")
    values.update(overrides)
    return mock.MagicMock(**values)


# ------------------------------------------------------------------- the candidate lists

def test_the_four_out_of_box_processes_need_only_two_closed_values():
    assert core.CLOSED_STATE_CANDIDATES == ("Closed", "Done")


def test_reopen_needs_three_because_scrum_tasks_differ_from_scrum_backlog_items():
    assert core.REOPEN_STATE_CANDIDATES == ("New", "To Do", "Proposed")


def test_an_unset_value_yields_every_candidate_in_order():
    assert core.state_candidates("", core.CLOSED_STATE_CANDIDATES) == ["Closed", "Done"]
    assert core.state_candidates(None, core.CLOSED_STATE_CANDIDATES) == ["Closed", "Done"]


def test_an_explicit_value_is_used_alone_with_no_fallback():
    """The derived-process escape hatch. An operator who says 'Retired' means it -- silently
    trying 'Closed' afterwards would put the work item in a state they did not ask for."""
    assert core.state_candidates("Retired", core.CLOSED_STATE_CANDIDATES) == ["Retired"]


def test_an_unexpanded_azure_placeholder_counts_as_unset():
    assert core.state_candidates("$(MEND_CLOSEDSTATE)", core.CLOSED_STATE_CANDIDATES) \
        == ["Closed", "Done"]


def test_surrounding_whitespace_is_stripped_not_sent_to_azure():
    assert core.state_candidates("  Done  ", core.CLOSED_STATE_CANDIDATES) == ["Done"]


# ------------------------------------------------------------------- the fallback attempt

def _patch_results(*results):
    """call_azure_api side effects: each entry is (response, errorcode)."""
    return mock.patch.object(core, "call_azure_api", side_effect=list(results))


def _states_sent(api):
    return [call.kwargs["data"][0]["value"] for call in api.call_args_list]


def test_a_working_board_closes_on_the_first_candidate_with_no_wasted_call():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results(({"id": 42}, 0)) as api:
        assert core.apply_close(42, ["Closed", "Done"]) is True
    assert _states_sent(api) == ["Closed"]


def test_a_scrum_board_falls_through_to_done():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 42}, 0)) as api:
        assert core.apply_close(42, ["Closed", "Done"]) is True
    assert _states_sent(api) == ["Closed", "Done"]


def test_a_refused_transition_is_not_retried_with_a_different_state():
    """The state NAME was fine. Retrying would issue a second bad write and could land the item
    somewhere the operator never asked for."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((TRANSITION_REFUSED, 2)) as api:
        assert core.apply_close(42, ["Closed", "Done"]) is False
    assert _states_sent(api) == ["Closed"]


def test_when_every_candidate_is_rejected_the_error_names_all_of_them(caplog):
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), (UNSUPPORTED, 2)):
        with caplog.at_level("ERROR"):
            assert core.apply_close(42, ["Closed", "Done"]) is False
    assert "Closed" in caplog.text and "Done" in caplog.text
    assert "MEND_CLOSEDSTATE" in caplog.text
    # Which board, so an operator running 107 projects does not have to look up work item 42.
    assert "TestProj" in caplog.text
    assert "Task" in caplog.text


def test_an_explicit_state_is_attempted_once_and_never_followed_by_a_guess():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2)) as api:
        assert core.apply_close(42, ["Retired"]) is False
    assert _states_sent(api) == ["Retired"]


def test_a_bare_string_still_works_and_makes_exactly_one_attempt():
    """Back-compatible: callers passing one state get today's behaviour, no fallback."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2)) as api:
        assert core.apply_close(42, "Closed") is False
    assert _states_sent(api) == ["Closed"]


# ------------------------------------------------------------------- the per-project cache

def test_the_winning_state_is_remembered_so_only_the_first_item_pays():
    """A Scrum project has one wasted attempt on its first work item and none after. At 107
    projects the alternative is a rejected PATCH per closed item, every run."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 1}, 0), ({"id": 2}, 0)) as api:
        assert core.apply_close(1, ["Closed", "Done"]) is True
        assert core.apply_close(2, ["Closed", "Done"]) is True
    assert _states_sent(api) == ["Closed", "Done", "Done"]


def test_the_cache_is_per_azure_project_because_routing_spans_processes():
    """MEND_ROUTING sends different Mend projects to different Azure projects, which can sit on
    different processes. One cache for all of them would apply Scrum's answer to an Agile board."""
    conf = _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 1}, 0), ({"id": 2}, 0)) as api:
        assert core.apply_close(1, ["Closed", "Done"]) is True   # ScrumProj -> Done
        conf.azure_project = "AgileProj"
        assert core.apply_close(2, ["Closed", "Done"]) is True   # starts from Closed again
    assert _states_sent(api) == ["Closed", "Done", "Closed"]


def test_close_and_reopen_caches_do_not_contaminate_each_other():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 1}, 0), ({"id": 2}, 0)) as api:
        assert core.apply_close(1, ["Closed", "Done"]) is True
        assert core.apply_reopen(2, ["New", "To Do", "Proposed"]) is True
    assert _states_sent(api) == ["Closed", "Done", "New"]


# ------------------------------------------------------------------- reopen, same mechanism

def test_a_basic_board_reopens_to_to_do():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 42}, 0)) as api:
        assert core.apply_reopen(42, ["New", "To Do", "Proposed"]) is True
    assert _states_sent(api) == ["New", "To Do"]


def test_a_cmmi_board_reopens_to_proposed():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), (UNSUPPORTED, 2), ({"id": 42}, 0)) as api:
        assert core.apply_reopen(42, ["New", "To Do", "Proposed"]) is True
    assert _states_sent(api) == ["New", "To Do", "Proposed"]


def test_the_reopen_error_names_the_reopen_variable_not_the_closed_one(caplog):
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), (UNSUPPORTED, 2), (UNSUPPORTED, 2)):
        with caplog.at_level("ERROR"):
            assert core.apply_reopen(42, ["New", "To Do", "Proposed"]) is False
    assert "MEND_REOPENSTATE" in caplog.text
    assert "MEND_CLOSEDSTATE" not in caplog.text


# ------------------------------------------------------------------- what reconcile_project passes

def test_reconcile_passes_the_candidate_lists_when_neither_variable_is_set():
    with mock.patch.object(core, "conf", _conf()):
        assert core.closed_state_candidates() == ["Closed", "Done"]
        assert core.reopen_state_candidates() == ["New", "To Do", "Proposed"]


def test_reconcile_passes_the_explicit_values_when_they_are_set():
    with mock.patch.object(core, "conf", _conf(closed_state="Retired", reopen_state="Reopened")):
        assert core.closed_state_candidates() == ["Retired"]
        assert core.reopen_state_candidates() == ["Reopened"]


# ---------------------------------------------- recognising an already-closed item on any process

def test_a_scrum_done_item_is_recognised_as_closed():
    """A LATENT BUG the candidate list fixes. reconcile._is_closed decides whether a work item is
    already closed. With a single "Closed" configured, a Scrum board's Done item was NOT recognised,
    so every run tried to close it again (a wasted PATCH that a state-reset process rule turns into
    real damage) and a returning finding never reopened it, because reopen only fires on an item
    seen as closed."""
    from mend_azure_wi_sync import reconcile
    assert reconcile._is_closed("Done", ["Closed", "Done"]) is True
    assert reconcile._is_closed("Closed", ["Closed", "Done"]) is True
    assert reconcile._is_closed("Active", ["Closed", "Done"]) is False


def test_is_closed_still_accepts_one_name_and_stays_case_insensitive():
    from mend_azure_wi_sync import reconcile
    assert reconcile._is_closed("closed", "Closed") is True
    assert reconcile._is_closed("  DONE  ", ["Done"]) is True
    assert reconcile._is_closed("Done", "Closed") is False


def test_an_empty_or_missing_state_is_never_treated_as_closed():
    """An item whose state we failed to read must not be silently skipped as already-closed."""
    from mend_azure_wi_sync import reconcile
    for state in ("", "   ", None):
        assert reconcile._is_closed(state, ["Closed", "Done"]) is False


# ------------------------------------------------- a comma-separated list, for a MIXED fleet
#
# MEND_CLOSEDSTATE is one global variable, and an explicit value is used alone. That combination
# cannot serve a fleet where one board runs a DERIVED process with a renamed state and another runs
# an out-of-box one: unset fails the derived board, and setting "Retired" fails the Agile board
# because explicit means no fallback. A list fixes it without per-board configuration, and matches
# the convention MEND_BRANCHES already uses.

def test_a_comma_separated_list_is_tried_in_order():
    assert core.state_candidates("Retired,Closed", core.CLOSED_STATE_CANDIDATES) \
        == ["Retired", "Closed"]


def test_whitespace_around_each_entry_is_stripped():
    assert core.state_candidates("  Retired , Done  ", core.CLOSED_STATE_CANDIDATES) \
        == ["Retired", "Done"]


def test_empty_entries_are_dropped_rather_than_sent_to_azure():
    """An empty System.State is rejected by Azure, so a trailing comma must not become an attempt."""
    assert core.state_candidates("Retired,,Closed,", core.CLOSED_STATE_CANDIDATES) \
        == ["Retired", "Closed"]


def test_a_list_of_nothing_but_separators_falls_back_to_the_defaults():
    for raw in (",", ",,,", "  ,  , "):
        assert core.state_candidates(raw, core.CLOSED_STATE_CANDIDATES) == ["Closed", "Done"], raw


def test_duplicates_are_collapsed_keeping_first_position():
    """Two attempts at the same state would just be a second rejected write."""
    assert core.state_candidates("Done,Closed,Done", core.CLOSED_STATE_CANDIDATES) \
        == ["Done", "Closed"]


def test_duplicates_differing_only_in_case_are_collapsed_too():
    assert core.state_candidates("Done,DONE,done", core.CLOSED_STATE_CANDIDATES) == ["Done"]


def test_an_explicit_list_is_still_never_extended_with_the_defaults():
    """The escape hatch's contract is unchanged: what an operator lists is what gets tried."""
    result = core.state_candidates("Retired,Archived", core.CLOSED_STATE_CANDIDATES)
    assert result == ["Retired", "Archived"]
    assert "Closed" not in result and "Done" not in result


def test_a_single_value_is_unaffected_by_list_support():
    assert core.state_candidates("Retired", core.CLOSED_STATE_CANDIDATES) == ["Retired"]


def test_a_mixed_fleet_closes_on_the_second_configured_state():
    """The scenario this exists for: a derived board wants 'Retired', an Agile board wants
    'Closed', and one variable now serves both."""
    with mock.patch.object(core, "conf", _conf(closed_state="Retired,Closed")), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 42}, 0)) as api:
        assert core.apply_close(42, core.closed_state_candidates()) is True
    assert _states_sent(api) == ["Retired", "Closed"]


def test_the_reopen_variable_takes_a_list_too():
    with mock.patch.object(core, "conf", _conf(reopen_state="Reopened,New")), \
         mock.patch.object(core, "STATE_RESOLVED", {}), \
         _patch_results((UNSUPPORTED, 2), ({"id": 42}, 0)) as api:
        assert core.apply_reopen(42, core.reopen_state_candidates()) is True
    assert _states_sent(api) == ["Reopened", "New"]
