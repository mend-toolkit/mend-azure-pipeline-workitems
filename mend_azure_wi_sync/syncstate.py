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
# Carries "{azure_project}|{product}/{project}" -- the address the reverse sync needs to visit
# this Mend project on its own, independent of whether the forward sync touched it this run
# (core.reverse_targets). Written only when it differs from what is already stored, so steady
# state is zero writes.
TAG_PROJECT = "azure-wi-project"

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

VERDICT_OK = "ok"
VERDICT_FAILED = "failed"

_TAG_FIELDS = {
    TAG_LASTRUN: "lastrun",
    TAG_FAILED: "failed",
    TAG_REVSYNC: "revsync",
    TAG_PROJECT: "project",
}


def _row_fields(row):
    """(token, tags) for a structurally readable row, else (None, None).

    A readable row is a dict with a non-blank string `token` and a dict `tags`. That, not the
    presence of one of our keys, is what proves the response shape: an org on its first run
    carries only CLI scan tags (CTX, commitId, repoFullName) and is perfectly readable.
    """
    if not isinstance(row, dict):
        return None, None
    token = row.get("token")
    tags = row.get("tags")
    if not isinstance(token, str) or not token.strip() or not isinstance(tags, dict):
        return None, None
    return token.strip(), tags


def _tag_values(value):
    """One tag's values as a sorted list of non-blank strings -- the 1.4 sweep returns a LIST.

    Verified live 2026-08-21: the sweep returns {"azure-wi-lastrun": ["2026-08-21 14:36:34",
    "2026-08-21 14:55:01"]}, a dict of lists, not of strings. The scalar form the docs imply is
    accepted too. Several values under one key is the NORMAL state, not an anomaly: saveProjectTag
    APPENDS rather than replaces (verified live the same day -- two runs, two values), so every
    run adds one.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return sorted(v.strip() for v in value if isinstance(v, str) and v.strip())


def parse_tag_values(rows) -> dict:
    """{token: {field: [value, …]}} -- every value under each of our keys, sorted.

    parse_tag_map picks one winner per field; this keeps the rest, because the superseded values
    are exactly what a pruning caller has to name in removeProjectTag. Append semantics mean the
    list grows by one per run per project otherwise, and the tag-value size limit is unverified.
    """
    state = {}
    for row in rows or []:
        token, tags = _row_fields(row)
        if not token:
            continue
        entry = {}
        for key, value in tags.items():
            if not isinstance(key, str):
                continue
            field = _TAG_FIELDS.get(key.strip().lower())
            values = _tag_values(value)
            if field and values:
                entry.setdefault(field, []).extend(values)
        if entry:
            state[token] = {f: sorted(set(v)) for f, v in entry.items()}
    return state


def parse_raw_tags(rows) -> dict:
    """{token: {raw tag key: [values]}} -- every tag on every project, ours and everyone else's.

    parse_tag_values deliberately keeps only the four keys this module owns, keyed by field
    name, because parse_tag_map derives its winners from it. Routing needs the raw keys
    (azure-project, azure-repo, azure-branch) under their own names, so it gets its own reader
    over the same rows rather than a widened one whose extra keys could reach parse_tag_map.
    """
    state = {}
    for row in rows or []:
        token, tags = _row_fields(row)
        if not token:
            continue
        entry = {}
        for key, value in tags.items():
            if not isinstance(key, str) or not key.strip():
                continue
            values = _tag_values(value)
            if values:
                entry[key.strip()] = values
        state[token] = entry
    return state


def field_for(key) -> str:
    """Tag key -> the field name parse_tag_values stores it under, "" for a key we do not own."""
    return _TAG_FIELDS.get((key or "").strip().lower(), "")


def superseded(values, winner) -> list:
    """The values under one key that are NOT the one in use — what a prune must remove.

    Never returns the winner, so a caller that saves first and prunes second can never delete
    the value it just wrote.
    """
    return [v for v in (values or []) if v != winner]


def count_parseable_rows(rows) -> int:
    """How many rows the parser could structurally read. core's shape guard needs this to tell
    "the response shape is wrong" apart from "no project has been tagged yet"."""
    return len([1 for row in (rows or []) if _row_fields(row)[0]])


def parse_tag_map(rows) -> dict:
    """Project tag rows -> {token: {lastrun, failed, revsync, project}}, keys present only when tagged.

    Deliberately tolerant: a malformed row is skipped, never fatal. This runs over every project
    in the organization, so one bad row must not cost the whole run its state.

    The LATEST value wins where a key carries several. saveProjectTag appends, so a project that
    has run twice legitimately carries two watermarks and the newer one is the true one — taking
    the earliest would pin the window to the first run forever and re-scan all of history on
    every run. Timestamps are TS_FORMAT, which sorts lexicographically, so max() is the latest.
    """
    return {token: {field: max(values) for field, values in entry.items()}
            for token, entry in parse_tag_values(rows).items()}


def _parse(stamp):
    """Timestamp string -> datetime, or None. Unparseable is treated as absent, never fatal."""
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        return datetime.datetime.strptime(stamp.strip(), TS_FORMAT)
    except ValueError:
        return None


def _floor(now_stamp, max_hours):
    """`now_stamp - max_hours` as a datetime. The one place the lookback bound is computed."""
    now = _parse(now_stamp) or datetime.datetime.now()
    return now - datetime.timedelta(hours=int(max_hours))


def clamp(stamp, now_stamp, max_hours) -> str:
    """The later of `stamp` and `now_stamp - max_hours`. The flooring primitive.

    For values the tool DERIVES for itself — the selection floor, a MEND_RESET window — where
    flooring only bounds cost. It must never be applied to a stored per-project watermark:
    moving a present watermark forward skips the gap between it and the new start, and the
    following OK verdict then closes that gap permanently. Use keep_or_clamp for those.
    A missing or unparseable stamp yields the floor, which is the wide-and-safe answer for
    "I do not know when this last synced".
    """
    own = _parse(stamp)
    floor = _floor(now_stamp, max_hours)
    return (max(own, floor) if own else floor).strftime(TS_FORMAT)


def keep_or_clamp(stamp, now_stamp, max_hours) -> str:
    """A stored watermark exactly as stored, however old; only an absent one is floored.

    A watermark present but older than max_hours means this project genuinely has not synced
    since then — a project whose work item writes keep being rejected keeps a frozen watermark
    and is retried every run. Flooring it would hand it a window starting after its own
    watermark, and the OK verdict on the run where the operator finally fixes the cause would
    write `lastrun = todate` over the gap, losing everything in it forever.
    """
    own = _parse(stamp)
    if own is None:
        return clamp(None, now_stamp, max_hours)
    return own.strftime(TS_FORMAT)


def is_stale(stamp, now_stamp, max_hours) -> bool:
    """True when `stamp` is present and older than the max_hours floor.

    keep_or_clamp honours such a watermark, so the resulting window is wider than
    MEND_MAXLOOKBACK and the operator has to be told which project widened it. This module
    stays pure (routing.py and enrichment.py hold no logger either), so the caller logs.
    """
    own = _parse(stamp)
    return bool(own and own < _floor(now_stamp, max_hours))


def window_start(token, state, todate, max_hours, reset, reset_hours) -> str:
    """The fromDateTime for one Mend project's fetch_prj_policy call."""
    if reset:
        # MEND_RESET is the explicit full-history escape hatch and ignores stored state entirely.
        return clamp(None, todate, reset_hours)
    own = (state or {}).get(token) or {}
    return keep_or_clamp(own.get("lastrun"), todate, max_hours)


def selection_floor(state, seed, todate, max_hours, reset, reset_hours) -> str:
    """The fromDateTime for the one global get_prj_list_modified call.

    min(), not max(). Only an ATTEMPTED project gets a verdict, so a project that was selected
    and never reached — job timeout, cancellation, OOM, any exception outside create_wi's try —
    carries no new tag at all. `max` would advance the floor past the moment that project was
    last scanned, and getOrganizationLastModifiedProjects can then never return it again: it was
    scanned before the floor. `min` can never be later than any project's own window start, and
    because every OK verdict writes `lastrun = todate`, it converges on `max` after one full
    pass. It is floored at max_hours because selecting a project whose window start is the
    clamped max lookback anyway buys nothing but ~5 Mend calls and a tag write.
    """
    if reset:
        return clamp(None, todate, reset_hours)
    stamps = [s for s in (_parse((v or {}).get("lastrun")) for v in (state or {}).values()) if s]
    if stamps:
        return clamp(min(stamps).strftime(TS_FORMAT), todate, max_hours)
    return seed.strip() if isinstance(seed, str) and seed.strip() \
        else clamp(None, todate, max_hours)


def build_selection(modified, state) -> list:
    """Projects to process: those Mend reports modified, plus those still flagged failed.

    The union is the whole point. Without it a project whose work items failed is never revisited,
    because Mend will not report it modified again until it is rescanned. Sorted so the run log is
    diffable, the same reason routing.build_table sorts.
    """
    retry = [token for token, entry in (state or {}).items() if (entry or {}).get("failed")]
    return sorted(set(modified or []) | set(retry))


def failed_stamp(token, state) -> str:
    """The TAG_FAILED value the read-once state map holds for one project, "" when it holds none."""
    return ((state or {}).get(token) or {}).get("failed") or ""


def tag_ops(verdict, todate, stored_failed="") -> list:
    """Verdict -> ordered (op, key, value) tuples. Empty when the project was never attempted.

    The remove is emitted ONLY when the state map actually carried a TAG_FAILED value, and
    carries that value rather than "". removeProjectTag matches on the value (verified live
    2026-08-21), so "" would name nothing; and whether it tolerates an absent key is still
    unverified, where an unconditional remove would error on every healthy run, falsely report
    the sync state unavailable and burn the once-per-run warning budget that every genuine save
    failure needs.
    """
    if verdict == VERDICT_OK:
        ops = [("save", TAG_LASTRUN, todate)]
        if isinstance(stored_failed, str) and stored_failed.strip():
            ops.append(("remove", TAG_FAILED, stored_failed.strip()))
        return ops
    if verdict == VERDICT_FAILED:
        return [("save", TAG_FAILED, todate)]
    return []
