from mend_azure_wi_sync import core

TITLE = "log4j-core: 3 vulnerabilities (highest severity is 9.8)"


def test_exact_tag_matches():
    core.exist_wis = [{TITLE: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 4821


def test_prefix_overlapping_project_does_not_match():
    """The defect: 'ProductX/api' must not match a work item tagged 'ProductX/api-client'."""
    core.exist_wis = [{TITLE: {4821: "ProductX/api-client; security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 0


def test_reverse_direction_also_does_not_match():
    core.exist_wis = [{TITLE: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api-client") == 0


def test_different_title_does_not_match():
    core.exist_wis = [{TITLE: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id(id="some other title", project_name="ProductX/api") == 0


def test_empty_cache_returns_zero():
    core.exist_wis = []
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 0


def test_picks_one_id_when_duplicates_exist():
    """Pre-existing duplicates must resolve to a single id, not crash."""
    core.exist_wis = [
        {TITLE: {4821: "ProductX/api; security vulnerability"}},
        {TITLE: {4999: "ProductX/api; security vulnerability"}},
    ]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") in (4821, 4999)


def test_malformed_entry_is_ignored_not_fatal():
    """A bad cache entry must not suppress a good match elsewhere in the list."""
    core.exist_wis = [
        {TITLE: 12345},
        {TITLE: {4821: "ProductX/api; security vulnerability"}},
    ]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 4821
