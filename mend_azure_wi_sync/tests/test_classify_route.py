from mend_azure_wi_sync.routing import LOUD_OUTCOMES, Route, classify

KNOWN = {"Platform", "Tools"}
PATTERNS = "main,master"


def test_fully_tagged_default_branch_is_ok():
    route = Route(azure_project="Platform", repo="api", branch="refs/heads/main")
    assert classify(route, KNOWN, PATTERNS) == "ok"


def test_missing_destination_tag_is_no_target():
    route = Route(repo="api", branch="refs/heads/main")
    assert classify(route, KNOWN, PATTERNS) == "no-target"



def test_non_default_branch_is_branch_filtered():
    route = Route(azure_project="Platform", repo="api", branch="refs/heads/feature/x")
    assert classify(route, KNOWN, PATTERNS) == "branch-filtered"


def test_destination_that_does_not_exist_is_unknown_target():
    route = Route(azure_project="Typo", repo="api", branch="refs/heads/main")
    assert classify(route, KNOWN, PATTERNS) == "unknown-target"


def test_missing_branch_tag_is_loud():
    """A destination with no branch means the scan template is missing a field. If that
    is the shared template, it is missing for all 400 repos — it must not be quiet."""
    route = Route(azure_project="Platform", repo="api")
    assert classify(route, KNOWN, PATTERNS) == "missing-branch-tag"
    assert "missing-branch-tag" in LOUD_OUTCOMES


def test_no_target_takes_precedence_over_everything():
    """An untagged project is un-onboarded, not misconfigured."""
    assert classify(Route(branch="refs/heads/feature/x"), KNOWN, PATTERNS) == "no-target"
    assert classify(Route(), KNOWN, PATTERNS) == "no-target"


def test_a_missing_branch_tag_takes_precedence_over_unknown_target():
    route = Route(azure_project="Typo", repo="api")
    assert classify(route, KNOWN, PATTERNS) == "missing-branch-tag"


def test_branch_filtering_takes_precedence_over_unknown_target():
    """A branch we never sync stays quiet even if its destination is also wrong, so
    feature-branch scans cannot flood the loud categories."""
    route = Route(azure_project="Typo", branch="refs/heads/feature/x")
    assert classify(route, KNOWN, PATTERNS) == "branch-filtered"


def test_quiet_outcomes_are_not_loud():
    assert "no-target" not in LOUD_OUTCOMES
    assert "branch-filtered" not in LOUD_OUTCOMES
