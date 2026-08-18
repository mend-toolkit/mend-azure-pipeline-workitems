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


def test_get_azure_prj_id_finds_a_project_past_the_first_page():
    """Regression: the unpaginated lookup made projects 101+ invisible to set_lastrun."""
    page1 = {"value": [{"name": f"P{i}", "id": f"id-{i}"} for i in range(100)]}
    page2 = {"value": [{"name": "Platform", "id": "id-platform"}]}
    with mock.patch.object(core, "conf", mock.MagicMock()), \
         mock.patch.object(core, "call_azure_api", side_effect=[(page1, 0), (page2, 0)]):
        assert core.get_azure_prj_id("Platform") == "id-platform"


def test_get_azure_prj_id_stops_early_when_found():
    """A single short page proves nothing about early exit - it would pass equally for an
    implementation that fetches every page and searches at the end. Put the match on page 3
    of 5 (full 100-item pages before and after it) and assert exactly 3 calls happened, so
    pages 4 and 5 provably were never fetched."""
    page1 = {"value": [{"name": f"P{i}", "id": f"id-{i}"} for i in range(100)]}
    page2 = {"value": [{"name": f"Q{i}", "id": f"id-q{i}"} for i in range(100)]}
    page3 = {"value": [{"name": f"R{i}", "id": f"id-r{i}"} for i in range(99)] +
                       [{"name": "Platform", "id": "id-platform"}]}
    page4 = {"value": [{"name": f"S{i}", "id": f"id-s{i}"} for i in range(100)]}
    page5 = {"value": [{"name": f"T{i}", "id": f"id-t{i}"} for i in range(50)]}
    with mock.patch.object(core, "conf", mock.MagicMock()), \
         mock.patch.object(core, "call_azure_api",
                           side_effect=[(page1, 0), (page2, 0), (page3, 0),
                                       (page4, 0), (page5, 0)]) as api:
        assert core.get_azure_prj_id("Platform") == "id-platform"
    assert api.call_count == 3


def test_get_azure_prj_id_skips_a_failed_page_and_still_returns_empty_string():
    """A None sentinel page (failure) must not break get_azure_prj_id's contract: not found
    still returns "", not raise."""
    page1 = {"value": [{"name": f"P{i}", "id": f"id-{i}"} for i in range(100)]}
    with mock.patch.object(core, "conf", mock.MagicMock()), \
         mock.patch.object(core, "call_azure_api",
                           side_effect=[(page1, 0), ({"message": "denied"}, 2)]):
        assert core.get_azure_prj_id("NotThere") == ""
