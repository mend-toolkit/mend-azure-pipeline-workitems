from unittest import mock

from mend_azure_wi_sync import core


def test_empty_reponame_is_not_backfilled_under_routing():
    """update_properties runs on every call_azure_api. Backfilling reponame with the
    Azure project name would tag work items with a repo that does not exist."""
    conf = core.startup()
    conf.routing = "true"
    conf.azure_project = "Platform"
    conf.reponame = ""
    conf.update_properties()
    assert conf.reponame == ""


def test_empty_reponame_still_backfills_when_routing_is_off():
    """Legacy behaviour: $MEND_REPONAME defaults to the Azure project name."""
    conf = core.startup()
    conf.routing = "false"
    conf.azure_project = "Platform"
    conf.reponame = ""
    conf.update_properties()
    assert conf.reponame == "Platform"


def test_explicit_reponame_survives_update_properties():
    conf = core.startup()
    conf.routing = "true"
    conf.azure_project = "Platform"
    conf.reponame = "api-client"
    conf.update_properties()
    assert conf.reponame == "api-client"
