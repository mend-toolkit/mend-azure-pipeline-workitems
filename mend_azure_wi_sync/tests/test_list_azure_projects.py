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


def test_mid_pagination_failure_discards_partial_names_instead_of_returning_them():
    """Regression: a page-2 failure after a successful page-1 must not surface as a
    truncated-but-real-looking 100-name set - that is the exact silent-truncation bug
    this task exists to eliminate, recurring one level up."""
    page1 = {"value": [{"name": f"P{i}"} for i in range(100)]}
    with mock.patch.object(core, "call_azure_api",
                           side_effect=[(page1, 0), ({"message": "denied"}, 2)]) as api:
        assert core.list_azure_projects() is None
    assert api.call_count == 2


def test_fully_successful_multi_page_sweep_still_returns_the_complete_set():
    page1 = {"value": [{"name": f"P{i}"} for i in range(100)]}
    page2 = {"value": [{"name": f"Q{i}"} for i in range(100)]}
    page3 = {"value": [{"name": "Last"}]}
    with mock.patch.object(core, "call_azure_api",
                           side_effect=[(page1, 0), (page2, 0), (page3, 0)]) as api:
        names = core.list_azure_projects()
    assert api.call_count == 3
    assert len(names) == 201
    assert "Last" in names
