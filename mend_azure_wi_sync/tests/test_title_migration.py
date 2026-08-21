from mend_azure_wi_sync import core
from mend_azure_wi_sync import identity

TAGS = "ProductX/api; security vulnerability"


def _resolve(new_title, lib_name, project_name):
    """Calls the SAME function create_wi calls -- not a copy of its logic."""
    return core.resolve_wi_id(
        new_title,
        lambda t: identity.is_legacy_vulnerability_title(t, lib_name),
        project_name=project_name)


def test_a_legacy_work_item_is_found_by_the_new_title_lookup():
    """The migration case: the item was created before this change and must be reused."""
    core.exist_wis = [
        {"log4j-core: 3 vulnerabilities (highest severity is 9.8)": {4821: TAGS}}]
    assert _resolve("log4j-core", "log4j-core", "ProductX/api") == 4821


def test_an_already_migrated_work_item_is_found_by_exact_title():
    core.exist_wis = [{"log4j-core": {4821: TAGS}}]
    assert _resolve("log4j-core", "log4j-core", "ProductX/api") == 4821


def test_suppressing_a_vulnerability_no_longer_orphans_the_work_item():
    """The defect this plan exists to fix. Under the old title the count changed from 3 to 2,
    the exact match missed, and a duplicate was created while the original stayed open."""
    core.exist_wis = [{"log4j-core": {4821: TAGS}}]
    # Two vulnerabilities today, one tomorrow -- the title is identical either way.
    assert identity.vulnerability_title("log4j-core") == "log4j-core"
    assert _resolve("log4j-core", "log4j-core", "ProductX/api") == 4821


def test_a_different_library_is_not_claimed():
    core.exist_wis = [
        {"log4j-core: 3 vulnerabilities (highest severity is 9.8)": {4821: TAGS}}]
    assert _resolve("log4j", "log4j", "ProductX/api") == 0


def test_nothing_matches_in_an_empty_project():
    core.exist_wis = []
    assert _resolve("log4j-core", "log4j-core", "ProductX/api") == 0
