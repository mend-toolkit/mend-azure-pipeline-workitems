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
