import os

import pytest

from mend_azure_wi_sync import core


@pytest.mark.live
def test_load_wi_json():
    """Hits the live Azure DevOps API. Requires MEND_AZUREURI / MEND_AZUREPROJECT and a
    credential: either MEND_AZUREPAT or the Entra trio.

    load_wi_json exit(-1)s when the project is unreadable, so without the guard an
    unconfigured `pytest -m live` reports a SystemExit failure here before it reaches any
    of the Entra live tests.
    """
    missing = [name for name in ("MEND_AZUREURI", "MEND_AZUREPROJECT")
               if not os.environ.get(name)]
    if not os.environ.get("MEND_AZUREPAT") and not all(
            os.environ.get(name) for name in ("MEND_AZURETENANTID", "MEND_AZURECLIENTID",
                                              "MEND_AZURECLIENTSECRET")):
        missing.append("MEND_AZUREPAT or the MEND_AZURETENANTID/CLIENTID/CLIENTSECRET trio")
    if missing:
        pytest.skip(f"live Azure DevOps credentials not set: {', '.join(missing)}")
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
