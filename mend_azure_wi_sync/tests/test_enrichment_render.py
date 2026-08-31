from mend_azure_wi_sync import enrichment as en


def test_format_reachability_ignores_a_non_string_leaf():
    # dict.get() raises TypeError: unhashable type on a dict/list key. _get only guarantees
    # the CONTAINER is a dict, never the leaf type, and this formatter is called unguarded
    # from inside create_wi -- an exception here would silently drop every work item for
    # the project while the run still reported success.
    assert en.format_reachability({"reachability": {"unexpected": "object"}}) == en.NO_DATA
    assert en.format_reachability({"reachability": ["unexpected"]}) == en.NO_DATA


def test_format_exploit_ignores_a_non_string_leaf():
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": {"unexpected": "object"}}}}
    ) == en.NO_DATA
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": ["unexpected"]}}}
    ) == en.NO_DATA
