"""Work item identity: how a title is composed, and how the titles it replaces are recognised.

Pure module -- no I/O, no globals, no Config. Same shape as routing.py and enrichment.py.

Idempotency depends entirely on the work item title (see CLAUDE.md). A title must therefore
depend only on values that do not move while the finding exists: the library name, and for
per-CVE mode the CVE identifier. The shipped titles embedded a vulnerability count and a
severity score, both of which change when a vulnerability is suppressed, rescored or fixed --
so suppressing one CVE renamed the work item, missed the match, created a duplicate and left
the original open. Suppression grew the backlog.
"""


def vulnerability_title(lib_name: str) -> str:
    """MEND_DEPENDENCY=true: one work item per vulnerable library."""
    return (lib_name or "").strip()


def cve_title(vul_name: str, lib_name: str) -> str:
    """MEND_DEPENDENCY=false: one work item per CVE."""
    return f"{(vul_name or '').strip()} detected in {(lib_name or '').strip()}"


def license_title(lib_name: str) -> str:
    """Unchanged from the shipped format -- already keyed on the library alone."""
    return f"License Policy Violation detected in {(lib_name or '').strip()}"
