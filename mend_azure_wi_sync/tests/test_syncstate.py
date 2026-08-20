from mend_azure_wi_sync import syncstate


def test_parses_our_three_tags_and_ignores_others():
    rows = [{"name": "p", "token": "tok-1", "tags": {
        "azure-wi-lastrun": "2026-08-20 10:00:00",
        "azure-wi-failed": "2026-08-19 10:00:00",
        "azure-wi-revsync": "2026-08-20 09:00:00",
        "azure-project": "Payments",
    }}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {
        "lastrun": "2026-08-20 10:00:00",
        "failed": "2026-08-19 10:00:00",
        "revsync": "2026-08-20 09:00:00",
    }}


def test_a_project_with_no_relevant_tags_is_omitted():
    rows = [{"token": "tok-1", "tags": {"azure-project": "Payments"}}]
    assert syncstate.parse_tag_map(rows) == {}


def test_tag_keys_are_matched_case_insensitively_and_values_stripped():
    rows = [{"token": "tok-1", "tags": {"AZURE-WI-LASTRUN": "  2026-08-20 10:00:00  "}}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {"lastrun": "2026-08-20 10:00:00"}}


def test_malformed_rows_are_skipped_not_fatal():
    rows = [
        "not-a-dict",
        {"tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},   # no token
        {"token": "tok-2", "tags": "not-a-dict"},
        {"token": "", "tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},
        {"token": "tok-3", "tags": {"azure-wi-lastrun": 12345}},  # non-string value
        {"token": "tok-4", "tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},
    ]
    assert syncstate.parse_tag_map(rows) == {"tok-4": {"lastrun": "2026-08-20 10:00:00"}}


def test_empty_and_none_input():
    assert syncstate.parse_tag_map([]) == {}
    assert syncstate.parse_tag_map(None) == {}
