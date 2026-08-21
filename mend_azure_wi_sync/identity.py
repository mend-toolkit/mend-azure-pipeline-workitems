"""Work item identity: how a title is composed, and how the titles it replaces are recognised.

Pure module -- no I/O, no globals, no Config. Same shape as routing.py and enrichment.py.

Idempotency depends entirely on the work item title (see CLAUDE.md). A title must therefore
depend only on values that do not move while the finding exists: the library name, and for
per-CVE mode the CVE identifier. The shipped titles embedded a vulnerability count and a
severity score, both of which change when a vulnerability is suppressed, rescored or fixed --
so suppressing one CVE renamed the work item, missed the match, created a duplicate and left
the original open. Suppression grew the backlog.
"""

import re


def vulnerability_title(lib_name: str) -> str:
    """MEND_DEPENDENCY=true: one work item per vulnerable library."""
    return (lib_name or "").strip()


def cve_title(vul_name: str, lib_name: str) -> str:
    """MEND_DEPENDENCY=false: one work item per CVE."""
    return f"{(vul_name or '').strip()} detected in {(lib_name or '').strip()}"


def license_title(lib_name: str) -> str:
    """Unchanged from the shipped format -- already keyed on the library alone."""
    return f"License Policy Violation detected in {(lib_name or '').strip()}"


# The two shipped title formats this module replaces. Matching them lets an existing work item
# be found and renamed in place instead of orphaned; System.Title is already part of every PATCH
# body (core.create_wi_content), so no extra call is needed to perform the rename.
#
# Deletable one release after everyone has synced once. Until then, removing these strands every
# work item created before this change.

_LEGACY_DEPENDENCY_SUFFIX = re.compile(r": \d+ vulnerabilities \(highest severity is .*\)$")


def is_legacy_vulnerability_title(title: str, lib_name: str) -> bool:
    """Matches 'log4j-core: 3 vulnerabilities (highest severity is 9.8)'."""
    lib = (lib_name or "").strip()
    if not title or not lib:
        return False
    if not title.startswith(f"{lib}:"):
        return False
    # Anchoring on the library prefix alone would let 'log4j' claim 'log4j-core'; the remainder
    # must be exactly the generated suffix.
    return _LEGACY_DEPENDENCY_SUFFIX.fullmatch(title[len(lib):]) is not None


def is_legacy_cve_title(title: str, vul_name: str, lib_name: str) -> bool:
    """Matches 'CVE-2021-44228 (High) detected in log4j-core'."""
    vul = (vul_name or "").strip()
    lib = (lib_name or "").strip()
    if not title or not vul or not lib:
        return False
    pattern = rf"^{re.escape(vul)} \(.*\) detected in {re.escape(lib)}$"
    return re.fullmatch(pattern, title) is not None
