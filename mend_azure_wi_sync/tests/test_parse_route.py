from mend_azure_wi_sync.routing import Route, parse_route


def _tags(**kv):
    return [{"key": k, "value": v} for k, v in kv.items()]


def test_parses_a_complete_tag_set():
    route = parse_route(_tags(**{"azure-project": "Platform", "azure-repo": "api-client",
                                 "azure-branch": "refs/heads/main", "azure-schema": "1"}))
    assert route.azure_project == "Platform"
    assert route.repo == "api-client"
    assert route.branch == "refs/heads/main"
    assert route.schema == "1"


def test_ignores_unrelated_tags():
    route = parse_route(_tags(**{"team": "payments", "azure-project": "Platform"}))
    assert route.azure_project == "Platform"
    assert route.repo == ""


def test_no_tags_yields_an_empty_route():
    assert parse_route([]) == Route()
    assert parse_route(None) == Route()


def test_branch_value_keeps_its_slashes():
    route = parse_route(_tags(**{"azure-branch": "refs/heads/release/1.2"}))
    assert route.branch == "refs/heads/release/1.2"


def test_whitespace_is_stripped_from_keys_and_values():
    route = parse_route([{"key": "  azure-project  ", "value": "  Platform  "}])
    assert route.azure_project == "Platform"


def test_keys_are_matched_case_insensitively():
    route = parse_route([{"key": "Azure-Project", "value": "Platform"}])
    assert route.azure_project == "Platform"


def test_malformed_entries_are_skipped_not_fatal():
    route = parse_route([None, {}, {"key": "azure-project"}, "not-a-dict",
                         {"key": "azure-project", "value": "Platform"}])
    assert route.azure_project == "Platform"


def test_repeated_key_takes_the_last_value():
    """Deliberately simple. A repo moving between Azure projects is not a concern here."""
    route = parse_route([{"key": "azure-project", "value": "Old"},
                         {"key": "azure-project", "value": "New"}])
    assert route.azure_project == "New"


def test_non_string_key_is_skipped_not_fatal():
    route = parse_route([{"key": 123, "value": "Platform"}])
    assert route.azure_project == ""


def test_non_string_value_is_skipped_not_fatal():
    route = parse_route([{"key": "azure-project", "value": 123}])
    assert route.azure_project == ""


def test_non_string_entry_before_a_good_entry_does_not_clobber_it():
    route = parse_route([{"key": "azure-schema", "value": 1},
                         {"key": "azure-project", "value": 123},
                         {"key": "azure-project", "value": "Platform"}])
    assert route.azure_project == "Platform"
    assert route.schema == ""
