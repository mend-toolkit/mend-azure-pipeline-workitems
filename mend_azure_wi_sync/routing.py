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
    # Last value wins for a repeated key. Deliberately simple: a repository moving between
    # Azure projects is out of scope for this client.
    route = Route()
    for raw in (tags or []):
        if not isinstance(raw, dict):
            continue
        key = raw.get("key")
        value = raw.get("value")
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        key = key.strip().lower()
        value = value.strip()
        attr = TAG_KEYS.get(key)
        if attr and value:
            setattr(route, attr, value)
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
