"""Diff Mend's current state against Azure DevOps, producing one action per work item.

Pure module -- it decides, it does not call. All HTTP stays in core.py.
"""

CREATE = "create"
UPDATE = "update"
CLOSE = "close"
REOPEN = "reopen"
SKIP = "skip"


def _is_closed(state, closed_state) -> bool:
    """True when `state` is one of the closed state names.

    `closed_state` is one name or a collection of them. Comparison is case-insensitive and ignores
    surrounding whitespace. An empty or missing state is not closed.
    """
    current = str(state or "").strip().casefold()
    if not current:
        return False
    names = [closed_state] if isinstance(closed_state, str) else (closed_state or [])
    return any(current == str(name or "").strip().casefold() for name in names)


def plan_actions(desired, actual, closed_state):
    """One action per work item key, for every key in `desired` or `actual`, each appearing exactly
    once. Keys are (kind, identity-key); see identity.py. Keys are matched, never inspected.

        in desired, absent from actual       -> CREATE
        in desired, present and closed       -> REOPEN
        in desired, present and open         -> UPDATE
        absent from desired, open            -> CLOSE
        absent from desired, already closed  -> SKIP

    SKIP means no API call is made for that work item.
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
            # Already closed and absent from desired: no API call.
            actions.append({"action": SKIP, "key": key, "id": current.get("id"), "entry": None})
        else:
            actions.append({"action": CLOSE, "key": key, "id": current.get("id"), "entry": None})

    return actions
