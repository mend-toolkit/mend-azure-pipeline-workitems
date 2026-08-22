"""Work item identity: the key a work item is matched on.

Pure module -- no I/O, no globals beyond a compiled regex, no Config. Same shape as routing.py
and enrichment.py.

Idempotency depends entirely on finding the right existing work item (see CLAUDE.md). The shipped
dependency-mode title embeds a vulnerability count and a highest-severity score, both of which move
when a vulnerability is suppressed, rescored or fixed -- so an exact-title match missed, a duplicate
was created and the original was left open. Suppression grew the backlog.

The title is worth keeping as it is: an operator scanning a backlog wants the count and the severity
at a glance. So the title stays, and the MATCH KEY drops the parts that move -- a dependency-mode
vulnerability work item is identified by its library name alone, whatever numbers the title carries.

Licenses keep exact-title matching: `License Policy Violation detected in {lib}` has no moving parts.
Per-CVE mode (MEND_DEPENDENCY=false) also keeps exact-title matching, by explicit decision -- which
means a rescore there still orphans the work item. That is a known, accepted defect, not an oversight.
"""

import re

# The shipped dependency-mode vulnerability title is
#     f"{lib_name}: {len(relevant_vuls)} vulnerabilities (highest severity is {max_severity})"
# Everything after the library name is a wildcard, so the count and score can change freely without
# changing which work item the title identifies. max_severity is "" when Mend has not scored
# anything, so the score group must tolerate empty.
_TITLE_SUFFIX = re.compile(r": \d+ vulnerabilities \(highest severity is .*\)$")


def matches_library(title: str, lib_name: str) -> bool:
    """True when `title` is the dependency-mode vulnerability work item title for `lib_name`.

    Anchoring on the library prefix alone would let 'log4j' claim 'log4j-core'; the remainder must
    be exactly the generated suffix. `lib_name` is compared literally, never as a pattern, so a
    library whose name contains regex metacharacters cannot match more than itself.
    """
    lib = (lib_name or "").strip()
    if not title or not lib:
        return False
    if not title.startswith(f"{lib}:"):
        return False
    return _TITLE_SUFFIX.fullmatch(title[len(lib):]) is not None


def license_title(lib_name: str) -> str:
    """Unchanged from the shipped format -- matched exactly, so it must stay byte-identical."""
    return f"License Policy Violation detected in {(lib_name or '').strip()}"
