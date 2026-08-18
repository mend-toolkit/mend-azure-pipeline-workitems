from unittest import mock

from mend_azure_wi_sync import core


def test_returns_the_set_of_project_names():
    payload = {"value": [{"name": "Platform"}, {"name": "Tools"}]}
    with mock.patch.object(core, "call_azure_api", return_value=(payload, 0)):
        assert core.list_azure_projects() == {"Platform", "Tools"}


def test_paginates_until_a_short_page_is_returned():
    page1 = {"value": [{"name": f"P{i}"} for i in range(100)]}
    page2 = {"value": [{"name": "Last"}]}
    with mock.patch.object(core, "call_azure_api",
                           side_effect=[(page1, 0), (page2, 0)]) as api:
        names = core.list_azure_projects()
    assert api.call_count == 2
    assert "Last" in names
    assert len(names) == 101


def test_returns_none_on_api_failure():
    with mock.patch.object(core, "call_azure_api", return_value=({"message": "denied"}, 2)):
        assert core.list_azure_projects() is None


def test_returns_none_on_malformed_payload():
    with mock.patch.object(core, "call_azure_api", return_value=({}, 0)):
        assert core.list_azure_projects() is None


def test_get_azure_prj_id_finds_a_project_past_the_first_page():
    """Regression: the unpaginated lookup made projects 101+ invisible to set_lastrun."""
    page1 = {"value": [{"name": f"P{i}", "id": f"id-{i}"} for i in range(100)]}
    page2 = {"value": [{"name": "Platform", "id": "id-platform"}]}
    with mock.patch.object(core, "conf", mock.MagicMock()), \
         mock.patch.object(core, "call_azure_api", side_effect=[(page1, 0), (page2, 0)]):
        assert core.get_azure_prj_id("Platform") == "id-platform"


def test_get_azure_prj_id_stops_early_when_found():
    page1 = {"value": [{"name": "Platform", "id": "id-platform"}]}
    with mock.patch.object(core, "conf", mock.MagicMock()), \
         mock.patch.object(core, "call_azure_api", side_effect=[(page1, 0)]) as api:
        assert core.get_azure_prj_id("Platform") == "id-platform"
    assert api.call_count == 1
