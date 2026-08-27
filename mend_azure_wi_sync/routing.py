import fnmatch
import os
import sys
from dataclasses import dataclass

sys.path.append(os.path.dirname(__file__))

# Mend tag key -> Route attribute. Project tags are key/value pairs (EntityTagDTO), promoted onto
# the project from its last CLI scan. Keys are matched lowercase.
TAG_KEYS = {
    "azure-project": "azure_project",
    "azure-repo": "repo",
    "azure-branch": "branch",
}


@dataclass
class Route:
    azure_project: str = ""
    repo: str = ""
    branch: str = ""

    def is_routable(self) -> bool:
        return bool(self.azure_project)


def parse_route(tags) -> Route:
    """Project tags -> Route.

    Accepts either shape Mend returns: {key: [value, ...]} or a list of {key, value} dicts. Keys
    outside TAG_KEYS are ignored, as are non-string keys and values. Values are stripped, and the
    last value wins for a repeated key.
    """
    route = Route()
    pairs = []
    if isinstance(tags, dict):
        for key, value in tags.items():
            values = value if isinstance(value, (list, tuple)) else [value]
            pairs.extend((key, v) for v in values)
    else:
        for raw in (tags or []):
            if isinstance(raw, dict):
                pairs.append((raw.get("key"), raw.get("value")))
    for key, value in pairs:
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        attr = TAG_KEYS.get(key.strip().lower())
        if attr and value.strip():
            setattr(route, attr, value.strip())
    return route


def branch_allowed(branch_ref: str, patterns: str) -> bool:
    """True when `branch_ref` matches any of the comma-separated fnmatch globs in `patterns`.

    `branch_ref` is a full ref (refs/heads/release/1.2); the refs/heads/ prefix is stripped before
    matching, so the patterns are written against the branch name (release/*). An empty ref never
    matches.
    """
    name = (branch_ref or "").strip()
    if not name:
        return False
    if name.startswith("refs/heads/"):
        name = name[len("refs/heads/"):]
    for pattern in (patterns or "").split(","):
        pattern = pattern.strip()
        if pattern and fnmatch.fnmatch(name, pattern):
            return True
    return False


SKIP_OK = "ok"
SKIP_NO_TARGET = "no-target"
SKIP_MISSING_BRANCH = "missing-branch-tag"
SKIP_BRANCH = "branch-filtered"
SKIP_UNKNOWN = "unknown-target"
SKIP_EXCLUDED = "scope-excluded"     # raised in core.py -- MEND_EXCLUDETOKEN
SKIP_OUT_OF_SCOPE = "out-of-scope"   # raised in core.py -- outside the product/project narrowing

# Outcomes logged at ERROR; every other outcome is logged quietly.
LOUD_OUTCOMES = (SKIP_MISSING_BRANCH, SKIP_UNKNOWN)


def classify(route: Route, known_projects: set, patterns: str) -> str:
    """One Route -> its routing outcome.

        no azure-project tag                      -> SKIP_NO_TARGET
        azure-project but no azure-branch tag      -> SKIP_MISSING_BRANCH
        branch does not match `patterns`           -> SKIP_BRANCH
        azure-project not in `known_projects`      -> SKIP_UNKNOWN
        otherwise                                  -> SKIP_OK
    """
    if not route.is_routable():
        return SKIP_NO_TARGET
    if not route.branch:
        return SKIP_MISSING_BRANCH
    if not branch_allowed(route.branch, patterns):
        return SKIP_BRANCH
    if route.azure_project not in (known_projects or set()):
        return SKIP_UNKNOWN
    return SKIP_OK


def build_table(routes: dict, known_projects: set, patterns: str, preset: dict = None):
    """{Mend project token: Route} -> (targets, outcomes).

    `targets` maps each Azure project to the [(token, route)] routed to it, holding only the
    SKIP_OK routes. `outcomes` carries every token's outcome. `preset` supplies outcomes core.py
    determined itself and takes precedence over classify(). Tokens are processed in sorted order,
    so the run log is diffable.
    """
    preset = preset or {}
    targets = {}
    outcomes = {}
    for token in sorted(routes or {}):
        route = routes[token]
        outcome = preset.get(token) or classify(route, known_projects, patterns)
        outcomes[token] = outcome
        if outcome == SKIP_OK:
            targets.setdefault(route.azure_project, []).append((token, route))
    return targets, outcomes


def coverage_report(outcomes: dict) -> str:
    """The outcomes map -> one log line: how many projects routed, and a sorted count per
    non-SKIP_OK outcome."""
    outcomes = outcomes or {}
    total = len(outcomes)
    routed = len([o for o in outcomes.values() if o == SKIP_OK])
    counts = {}
    for outcome in outcomes.values():
        counts[outcome] = counts.get(outcome, 0) + 1
    detail = ", ".join([f"{name}: {counts[name]}" for name in sorted(counts) if name != SKIP_OK])
    report = f"Routing coverage: {routed} of {total} Mend project(s) routed"
    return f"{report} ({detail})" if detail else report
