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
        key = (raw.get("key") or "").strip().lower()
        value = (raw.get("value") or "").strip()
        attr = TAG_KEYS.get(key)
        if attr and value:
            setattr(route, attr, value)
    return route
