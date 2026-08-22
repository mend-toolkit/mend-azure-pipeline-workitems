from mend_azure_wi_sync import core
from mend_azure_wi_sync import identity

TAGS = "ProductX/api; security vulnerability"


def _find(lib_name, project_name):
    """The lookup create_wi performs in dependency mode."""
    return core.check_wi_id_matching(
        lambda t: identity.matches_library(t, lib_name), project_name=project_name)


def test_finds_the_work_item_whatever_the_count_says():
    core.exist_wis = [
        {"log4j-core: 3 vulnerabilities (highest severity is 9.8)": {4821: TAGS}}]
    assert _find("log4j-core", "ProductX/api") == 4821


def test_suppressing_a_vulnerability_still_finds_the_same_item():
    """The defect this plan exists to fix. The count dropped 3 -> 2 and the score changed;
    under exact-title matching this missed, created a duplicate and stranded the original."""
    core.exist_wis = [
        {"log4j-core: 2 vulnerabilities (highest severity is 7.5)": {4821: TAGS}}]
    assert _find("log4j-core", "ProductX/api") == 4821


def test_still_requires_the_project_tag():
    core.exist_wis = [
        {"log4j-core: 3 vulnerabilities (highest severity is 9.8)":
            {4821: "ProductX/api-client; security vulnerability"}}]
    assert _find("log4j-core", "ProductX/api") == 0


def test_does_not_claim_a_different_library():
    core.exist_wis = [
        {"log4j-core: 3 vulnerabilities (highest severity is 9.8)": {4821: TAGS}}]
    assert _find("log4j", "ProductX/api") == 0


def test_does_not_claim_a_license_work_item():
    core.exist_wis = [
        {"License Policy Violation detected in log4j-core": {4821: TAGS}}]
    assert _find("log4j-core", "ProductX/api") == 0


def test_nothing_matches_in_an_empty_project():
    core.exist_wis = []
    assert _find("log4j-core", "ProductX/api") == 0


def test_licenses_are_matched_exactly_not_by_library():
    """Licenses keep exact-title matching -- their title has no moving parts."""
    core.exist_wis = [
        {"License Policy Violation detected in log4j-core": {4821: TAGS}}]
    assert core.check_wi_id(id=identity.license_title("log4j-core"),
                            project_name="ProductX/api") == 4821


def test_resolve_wi_id_is_gone():
    """The two-step lookup had no purpose once there is no legacy title shape."""
    assert not hasattr(core, "resolve_wi_id")
