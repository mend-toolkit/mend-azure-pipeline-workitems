import fnmatch
import os
import sys
from dataclasses import dataclass

sys.path.append(os.path.dirname(__file__))

# Mend tag key -> Route attribute. Project tags are key/value pairs (EntityTagDTO),
# promoted onto the project from its last CLI scan. Keys are matched lowercase.
TAG_KEYS = {
    "azure-project": "azure_project",
    "azure-repo": "repo",
    "azure-branch": "branch",
    "azure-schema": "schema",
}


@dataclass
class Route:
    azure_project: str = ""
    repo: str = ""
    branch: str = ""
    schema: str = ""

    def is_routable(self) -> bool:
        return bool(self.azure_project)


def parse_route(tags) -> Route:
    """Project tags -> Route. Accepts both shapes Mend returns.

    1.4 getOrganizationProjectTags gives {key: [value, ...]}; 2.0 /entities gave a list of
    EntityTagDTO {key, value}. Routing reads the 1.4 sweep now, but the list form is kept
    because it costs three lines and a caller passing it would otherwise silently route
    nothing.

    Last value wins for a repeated key. Deliberately simple: a repository moving between
    Azure projects is out of scope for this client.
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
    # The tag carries a full ref (refs/heads/release/1.2) because $(Build.SourceBranchName)
    # returns only the final path segment and cannot express "release/*". Strip the ref
    # prefix here so the configured patterns stay readable.
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
SKIP_SCHEMA = "schema-fault"
SKIP_BRANCH = "branch-filtered"
SKIP_UNKNOWN = "unknown-target"
SKIP_EXCLUDED = "scope-excluded"     # raised in core.py — MEND_EXCLUDETOKEN, deliberate
SKIP_OUT_OF_SCOPE = "out-of-scope"   # raised in core.py — outside the product/project narrowing

# Outcomes that should be logged at ERROR. no-target and branch-filtered are the normal
# state during rollout and must not drown out a real misconfiguration.
LOUD_OUTCOMES = (SKIP_SCHEMA, SKIP_UNKNOWN)


def classify(route: Route, known_projects: set, patterns: str) -> str:
    if not route.is_routable():
        return SKIP_NO_TARGET
    if not route.branch:
        # Tagged with a destination but no branch: the scan template is missing a field.
        # Distinct from branch-filtered, which is a policy decision we made on purpose.
        return SKIP_SCHEMA
    if not branch_allowed(route.branch, patterns):
        return SKIP_BRANCH
    if route.azure_project not in (known_projects or set()):
        return SKIP_UNKNOWN
    return SKIP_OK


def build_table(routes: dict, known_projects: set, patterns: str, preset: dict = None):
    # routes maps Mend project token -> Route. preset lets core.py inject outcomes it
    # determined itself (scope-excluded) without routing.py needing config awareness.
    # Sorted so the run log is diffable.
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
    outcomes = outcomes or {}
    total = len(outcomes)
    routed = len([o for o in outcomes.values() if o == SKIP_OK])
    counts = {}
    for outcome in outcomes.values():
        counts[outcome] = counts.get(outcome, 0) + 1
    detail = ", ".join([f"{name}: {counts[name]}" for name in sorted(counts) if name != SKIP_OK])
    report = f"Routing coverage: {routed} of {total} Mend project(s) routed"
    return f"{report} ({detail})" if detail else report
