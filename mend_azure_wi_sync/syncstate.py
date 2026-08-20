import datetime
import os
import sys

sys.path.append(os.path.dirname(__file__))

# Sync state is carried as Mend project tags rather than an Azure DevOps project property, so the
# tool needs no *Manage project properties* permission and state sits on the object it describes.
# Keys are lowercase and hyphenated to match routing's convention (routing.py:10-15). routing
# ignores keys it does not know (routing.py:41-43), so these are invisible to it.
TAG_LASTRUN = "azure-wi-lastrun"
TAG_FAILED = "azure-wi-failed"
TAG_REVSYNC = "azure-wi-revsync"

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

VERDICT_OK = "ok"
VERDICT_FAILED = "failed"

_TAG_FIELDS = {
    TAG_LASTRUN: "lastrun",
    TAG_FAILED: "failed",
    TAG_REVSYNC: "revsync",
}


def parse_tag_map(rows) -> dict:
    """Project tag rows -> {token: {lastrun, failed, revsync}}, keys present only when tagged.

    Deliberately tolerant: a malformed row is skipped, never fatal. This runs over every project
    in the organization, so one bad row must not cost the whole run its state.
    """
    state = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        token = row.get("token")
        tags = row.get("tags")
        if not isinstance(token, str) or not token.strip() or not isinstance(tags, dict):
            continue
        entry = {}
        for key, value in tags.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            field = _TAG_FIELDS.get(key.strip().lower())
            if field and value.strip():
                entry[field] = value.strip()
        if entry:
            state[token.strip()] = entry
    return state
