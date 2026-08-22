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


def test_entry_in_creation_shape_is_findable():
    """Entries appended at creation time must share the shape get_exist_wi produces.

    core.py appended {lib_name: int} — keyed by library rather than title, with a bare int
    where a {id: tags} dict belongs. Unreachable rather than harmful today, but backlog #4
    will iterate exist_wis for real and cannot tolerate a mixed shape.
    """
    core.exist_wis = [{TITLE: {4821: "ProductX/api,security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 4821


def test_project_name_with_surrounding_whitespace_still_matches():
    """The haystack tags are stripped by tag_set, but project_name itself must also be
    stripped, or a Mend product/project name with leading/trailing whitespace never matches."""
    core.exist_wis = [{TITLE: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="  ProductX/api  ") == 4821


def test_tag_match_differing_only_in_case():
    """Azure Boards tags are case-insensitive for identity and case-preserving on first
    creation; an existing 'productx/api' tag must still match a differently-cased needle."""
    core.exist_wis = [{TITLE: {4821: "productx/api; security vulnerability"}}]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 4821


def test_multi_key_entry_values_are_not_welded_together():
    """A multi-key entry's tag strings must be joined with ';' rather than '' — otherwise the
    last tag of one value welds onto the first tag of the next, inventing a phantom tag and
    losing a real one."""
    core.exist_wis = [{TITLE: {4821: "ProductX/ap", 4822: "i; security vulnerability"}}]
    # Joining with '' would produce "ProductX/api" out of "ProductX/ap" + "i" — a phantom tag
    # that must NOT be considered a match for "ProductX/api".
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 0


def test_two_repos_sharing_a_library_each_keep_their_own_item():
    """Not a duplicate — this is the design. Distinct tags mean distinct work items,
    even though the titles are byte-identical."""
    core.exist_wis = [
        {TITLE: {4821: "ProductX/api; security vulnerability"}},
        {TITLE: {4822: "ProductX/api-client; security vulnerability"}},
    ]
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api") == 4821
    assert core.check_wi_id(id=TITLE, project_name="ProductX/api-client") == 4822


LEGACY = "log4j-core: 3 vulnerabilities (highest severity is 9.8)"


def test_matching_finds_by_predicate():
    core.exist_wis = [{LEGACY: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id_matching(
        lambda t: t.startswith("log4j-core:"), project_name="ProductX/api") == 4821


def test_matching_still_requires_the_project_tag():
    """A predicate match with the wrong project tag must not resolve."""
    core.exist_wis = [{LEGACY: {4821: "ProductX/api-client; security vulnerability"}}]
    assert core.check_wi_id_matching(
        lambda t: t.startswith("log4j-core:"), project_name="ProductX/api") == 0


def test_matching_returns_zero_when_the_predicate_never_fires():
    core.exist_wis = [{LEGACY: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id_matching(
        lambda t: t == "something else", project_name="ProductX/api") == 0


def test_matching_ignores_a_malformed_entry_and_still_finds_a_good_one():
    core.exist_wis = [
        {LEGACY: 12345},
        {LEGACY: {4821: "ProductX/api; security vulnerability"}},
    ]
    assert core.check_wi_id_matching(
        lambda t: t.startswith("log4j-core:"), project_name="ProductX/api") == 4821


def test_a_raising_predicate_does_not_abort_the_search():
    """A bad predicate on one title must not suppress a match on another."""
    def boom(title):
        if title == "bad":
            raise ValueError("boom")
        return True

    core.exist_wis = [
        {"bad": {1: "ProductX/api"}},
        {LEGACY: {4821: "ProductX/api; security vulnerability"}},
    ]
    assert core.check_wi_id_matching(boom, project_name="ProductX/api") == 4821


def test_check_wi_id_still_matches_exactly_after_the_refactor():
    """Regression: the existing exact-match contract is unchanged."""
    core.exist_wis = [{LEGACY: {4821: "ProductX/api; security vulnerability"}}]
    assert core.check_wi_id(id=LEGACY, project_name="ProductX/api") == 4821
    assert core.check_wi_id(id="log4j-core", project_name="ProductX/api") == 0
