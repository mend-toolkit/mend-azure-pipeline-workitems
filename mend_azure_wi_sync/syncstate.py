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


def _parse(stamp):
    """Timestamp string -> datetime, or None. Unparseable is treated as absent, never fatal."""
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        return datetime.datetime.strptime(stamp.strip(), TS_FORMAT)
    except ValueError:
        return None


def clamp(stamp, now_stamp, max_hours) -> str:
    """The later of `stamp` and `now_stamp - max_hours`.

    Bounds the cost of a project that keeps failing: its window widens to the clamp and stops,
    instead of growing without limit. A missing or unparseable stamp yields the clamp, which is
    the wide-and-safe answer for "I do not know when this last synced".
    """
    now = _parse(now_stamp) or datetime.datetime.now()
    floor = now - datetime.timedelta(hours=int(max_hours))
    own = _parse(stamp)
    return (max(own, floor) if own else floor).strftime(TS_FORMAT)


def window_start(token, state, todate, max_hours, reset, reset_hours) -> str:
    """The fromDateTime for one Mend project's fetch_prj_policy call."""
    if reset:
        # MEND_RESET is the explicit full-history escape hatch and ignores stored state entirely.
        return clamp(None, todate, reset_hours)
    own = (state or {}).get(token) or {}
    return clamp(own.get("lastrun"), todate, max_hours)


def selection_floor(state, seed, todate, max_hours, reset, reset_hours) -> str:
    """The fromDateTime for the one global get_prj_list_modified call.

    max(), not min(): every project that did not succeed carries TAG_FAILED and is unioned into
    the selection regardless, so narrowing the modified-projects query cannot lose work.
    """
    if reset:
        return clamp(None, todate, reset_hours)
    stamps = [s for s in (_parse((v or {}).get("lastrun")) for v in (state or {}).values()) if s]
    if stamps:
        return max(stamps).strftime(TS_FORMAT)
    return seed.strip() if isinstance(seed, str) and seed.strip() \
        else clamp(None, todate, reset_hours)
