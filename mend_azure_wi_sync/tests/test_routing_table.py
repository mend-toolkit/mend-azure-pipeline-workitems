from mend_azure_wi_sync.routing import Route, build_table, coverage_report

KNOWN = {"Platform", "Tools"}
PATTERNS = "main,master"


def _route(project="Platform", repo="api", branch="refs/heads/main"):
    return Route(azure_project=project, repo=repo, branch=branch)


def test_groups_multiple_mend_projects_under_one_azure_project():
    routes = {"tok-a": _route(repo="api"), "tok-b": _route(repo="api-client")}
    targets, outcomes = build_table(routes, KNOWN, PATTERNS)
    assert set(targets) == {"Platform"}
    assert len(targets["Platform"]) == 2
    assert outcomes == {"tok-a": "ok", "tok-b": "ok"}


def test_separates_distinct_azure_projects():
    routes = {"tok-a": _route(project="Platform"), "tok-b": _route(project="Tools")}
    targets, _ = build_table(routes, KNOWN, PATTERNS)
    assert set(targets) == {"Platform", "Tools"}


def test_skipped_projects_are_absent_from_targets_but_present_in_outcomes():
    routes = {"tok-a": _route(), "tok-b": Route(repo="orphan")}
    targets, outcomes = build_table(routes, KNOWN, PATTERNS)
    assert len(targets["Platform"]) == 1
    assert outcomes["tok-b"] == "no-target"


def test_preset_outcomes_win_and_are_never_synced():
    """core.py decides scope-excluded from config; routing must not override it."""
    routes = {"tok-a": _route(), "tok-b": _route(repo="excluded")}
    targets, outcomes = build_table(routes, KNOWN, PATTERNS,
                                    preset={"tok-b": "scope-excluded"})
    assert outcomes["tok-b"] == "scope-excluded"
    assert [t for t, _ in targets["Platform"]] == ["tok-a"]


def test_empty_input_yields_empty_table():
    assert build_table({}, KNOWN, PATTERNS) == ({}, {})


def test_grouping_is_deterministic():
    """Stable ordering keeps run-to-run logs diffable."""
    routes = {"tok-b": _route(repo="b"), "tok-a": _route(repo="a")}
    targets, _ = build_table(routes, KNOWN, PATTERNS)
    assert [t for t, _ in targets["Platform"]] == ["tok-a", "tok-b"]


def test_coverage_report_states_routed_over_total():
    outcomes = {"a": "ok", "b": "ok", "c": "no-target", "d": "unknown-target"}
    assert "2 of 4" in coverage_report(outcomes)


def test_coverage_report_names_the_non_ok_outcomes():
    report = coverage_report({"a": "ok", "d": "unknown-target"})
    assert "unknown-target" in report


def test_coverage_report_handles_no_projects():
    assert "0 of 0" in coverage_report({})
