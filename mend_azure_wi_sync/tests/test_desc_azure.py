import pytest

from mend_azure_wi_sync.config import DescAzure
from mend_azure_wi_sync.tests.test_routing_config import _valid_conf


@pytest.mark.parametrize("azure_type", ["Bug", "BUG", "bug", "bUg"])
def test_bug_maps_to_repro_steps_in_any_case(azure_type):
    """Azure DevOps treats work item type names case-insensitively, so MEND_AZURETYPE
    arrives however the pipeline author typed it.

    This was live: `MEND_AZURETYPE: BUG` resolved to "", which made core.py's
    `if desc_field:` guard skip the description patch entirely — work items were created
    with a title, tags and priority but NO description in any field, silently.
    """
    assert DescAzure.get_name_by_value(azure_type) == "ReproSteps"


@pytest.mark.parametrize("azure_type", ["Task", "TASK", "task", "User Story", "USER STORY"])
def test_description_types_map_in_any_case(azure_type):
    assert DescAzure.get_name_by_value(azure_type) == "Description"


@pytest.mark.parametrize("azure_type", ["B", "ug", "Bug Report", "Tas", "", "Widget"])
def test_partial_and_unknown_values_do_not_match(azure_type):
    """The old check was `value in member.value` against the bare string "Bug", i.e. a
    substring test — so "B" and "ug" matched ReproSteps. Matching must be exact.
    """
    assert DescAzure.get_name_by_value(azure_type) == ""


def test_update_properties_derives_repro_steps_from_an_uppercase_type():
    """The end-to-end path that failed in the pipeline: MEND_AZURETYPE=BUG with
    MEND_DESCRIPTION unset must still resolve the description target.
    """
    conf = _valid_conf(azure_type="BUG", description="")
    conf.update_properties()
    assert conf.description == "ReproSteps"
