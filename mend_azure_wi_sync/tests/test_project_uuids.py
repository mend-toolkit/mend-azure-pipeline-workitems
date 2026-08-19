from unittest import mock

import pytest

from mend_azure_wi_sync import core


@pytest.fixture(autouse=True)
def _clear_entities_cache():
    core.entities_rows = None
    yield
    core.entities_rows = None


def _row(product, project, uuid):
    return {"product": {"name": product},
            "project": {"name": project, "uuid": uuid, "tags": []}}


def _payload(rows, last=True):
    return {"retVal": rows, "additionalData": {"isLastPage": str(last).lower()}}


def test_tokens_are_mapped_through_the_product_project_name_pair():
    # 1.4 tokens and 3.0 uuids are different identifier spaces (0 of 25 matched live), so
    # the join must go through names, exactly as fetch_project_tags does.
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names",
                           return_value={"tok-1": ("Prod", "Proj")}), \
         mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_payload([_row("Prod", "Proj", "uuid-1")]), 0)):
        assert core.resolve_project_uuids(["tok-1"]) == {"tok-1": "uuid-1"}


def test_an_unresolvable_token_is_simply_absent():
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names",
                           return_value={"tok-1": ("Prod", "Gone")}), \
         mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_payload([_row("Prod", "Proj", "uuid-1")]), 0)):
        assert core.resolve_project_uuids(["tok-1"]) == {}


def test_a_collided_name_pair_yields_no_uuid_rather_than_a_guess():
    rows = [_row("Prod", "Proj", "uuid-1"), _row("Prod", "Proj", "uuid-2")]
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names",
                           return_value={"tok-1": ("Prod", "Proj")}), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(_payload(rows), 0)):
        assert core.resolve_project_uuids(["tok-1"]) == {}


def test_name_resolution_or_entities_failure_returns_empty():
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names", return_value=None):
        assert core.resolve_project_uuids(["tok-1"]) == {}
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names",
                           return_value={"tok-1": ("Prod", "Proj")}), \
         mock.patch.object(core, "call_ws_api_v2", return_value=({}, 2)):
        assert core.resolve_project_uuids(["tok-1"]) == {}


def test_the_entities_sweep_runs_once_per_run():
    # Under routing, fetch_project_tags already pages /entities. Paying for it twice would
    # double the most expensive Mend call in the run.
    with mock.patch.object(core, "conf", mock.MagicMock(ws_org_token="ot")), \
         mock.patch.object(core, "_resolve_project_names",
                           return_value={"tok-1": ("Prod", "Proj")}), \
         mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_payload([_row("Prod", "Proj", "uuid-1")]), 0)) as call:
        core.resolve_project_uuids(["tok-1"])
        core.resolve_project_uuids(["tok-1"])
        core.fetch_project_tags(["tok-1"])
    assert call.call_count == 1
