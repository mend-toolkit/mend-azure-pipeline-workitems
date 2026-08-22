"""Diff Mend's current state against Azure DevOps, producing one action per work item.

Pure module -- it decides, it does not call. All HTTP stays in core.py.

The tool's job is to make Azure match Mend's CURRENT state. Until the 3.0 move that was
impossible: 1.4's policy API is a delta ("what was raised between these timestamps"), so a work
item's absence from a window meant nothing and nothing could ever be closed. 3.0 publishes
findingInfo.status explicitly, so absence from `desired` is now a statement about now.
"""

CREATE = "create"
UPDATE = "update"
CLOSE = "close"
REOPEN = "reopen"
SKIP = "skip"


def _is_closed(state, closed_state: str) -> bool:
    """Case-insensitive: Azure returns state names as the process defines them, and a case
    mismatch would turn a skip into a close, then a reopen, then a close -- an item flapping
    on every run."""
    return str(state or "").strip().casefold() == str(closed_state or "").strip().casefold()


def plan_actions(desired, actual, closed_state: str):
    """One action per work item key. Keys are (kind, library).

    Every key in `desired` or `actual` appears exactly once in the result: a key that was both
    created and closed would fight itself on every run.

    SKIP exists for one reason and it is load-bearing. An item that is already closed and should
    stay closed gets NO API call at all -- not a redundant close. If an Azure process rule
    reactivates a Closed work item whenever it is PATCHed (observed by Joshua, cause unconfirmed),
    then any call against a closed item reopens it and the item oscillates forever. Making no call
    is correct whether or not that rule exists, which is what lets this design ship without the
    answer.
    """
    desired = desired if isinstance(desired, dict) else {}
    actual = actual if isinstance(actual, dict) else {}
    actions = []

    for key, entry in desired.items():
        current = actual.get(key)
        if not current:
            actions.append({"action": CREATE, "key": key, "id": None, "entry": entry})
        elif _is_closed(current.get("state"), closed_state):
            actions.append({"action": REOPEN, "key": key, "id": current.get("id"), "entry": entry})
        else:
            actions.append({"action": UPDATE, "key": key, "id": current.get("id"), "entry": entry})

    for key, current in actual.items():
        if key in desired:
            continue
        if _is_closed(current.get("state"), closed_state):
            # Already closed and still gone: nothing to do, and deliberately no API call.
            actions.append({"action": SKIP, "key": key, "id": current.get("id"), "entry": None})
        else:
            actions.append({"action": CLOSE, "key": key, "id": current.get("id"), "entry": None})

    return actions
