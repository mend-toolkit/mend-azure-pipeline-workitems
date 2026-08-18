from mend_azure_wi_sync.core import tag_set


def test_splits_azure_read_format():
    """Azure DevOps returns System.Tags as '; '-delimited."""
    assert tag_set("ProductX/api; security vulnerability") == {
        "ProductX/api", "security vulnerability"}


def test_splits_tool_write_format():
    """core.py writes tags comma-joined; be safe against reading that form back."""
    assert tag_set("ProductX/api,security vulnerability") == {
        "ProductX/api", "security vulnerability"}


def test_strips_surrounding_whitespace():
    assert tag_set("  ProductX/api  ;  outdated library ") == {
        "ProductX/api", "outdated library"}


def test_drops_empty_entries():
    assert tag_set("ProductX/api;;") == {"ProductX/api"}


def test_empty_and_none_are_empty_sets():
    assert tag_set("") == set()
    assert tag_set(None) == set()


def test_prefix_overlapping_tags_are_distinct():
    """The whole point: 'ProductX/api' must not match 'ProductX/api-client'."""
    tags = tag_set("ProductX/api-client; security vulnerability")
    assert "ProductX/api" not in tags
    assert "ProductX/api-client" in tags


def test_matches_regardless_of_spacing():
    for raw in ("a;security vulnerability", "a; security vulnerability",
                "a ;  security vulnerability  "):
        assert "security vulnerability" in tag_set(raw)
