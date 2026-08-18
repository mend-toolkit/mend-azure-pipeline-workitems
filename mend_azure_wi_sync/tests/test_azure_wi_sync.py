import pytest

from mend_azure_wi_sync import core


@pytest.mark.live
def test_load_wi_json():
    """Hits the live Azure DevOps API. Requires WS_AZUREURI / WS_AZUREPAT / WS_AZUREPROJECT."""
    assert core.load_wi_json()


def test_globals_are_clean_at_test_start():
    assert core.exist_wis == []
    core.exist_wis.append({"dirty": {1: "tag"}})


def test_globals_are_clean_for_the_next_test():
    """Only meaningful because the previous test dirtied exist_wis."""
    assert core.exist_wis == []
