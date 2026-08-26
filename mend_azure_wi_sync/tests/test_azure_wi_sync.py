import pytest

from mend_azure_wi_sync import core


@pytest.mark.live
def test_load_wi_json():
    """Hits the live Azure DevOps API. Requires MEND_AZUREURI / MEND_AZUREPAT / MEND_AZUREPROJECT."""
    assert core.load_wi_json()


def test_globals_are_clean_at_test_start():
    assert core.exist_wis == []
    core.exist_wis.append({"dirty": {1: "tag"}})


def test_globals_are_clean_for_the_next_test():
    """Only meaningful because the previous test dirtied exist_wis."""
    assert core.exist_wis == []


def test_mend_reset_is_gone():
    """3.0 reports each project's full current state, so there is no window to reset and no
    MEND_RESET notice to log. The variable is gone from Config and from the varenvs map."""
    from mend_azure_wi_sync.config import Config, varenvs
    assert "reset" not in Config.__dataclass_fields__
    assert "maxlookback" not in Config.__dataclass_fields__
    assert not hasattr(varenvs, "wsreset")
    assert not hasattr(varenvs, "wsmaxlookback")
