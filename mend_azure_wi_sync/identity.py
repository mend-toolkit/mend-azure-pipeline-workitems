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

Per-CVE mode (MEND_DEPENDENCY=false) is matched the same way as dependency mode, for the same
reason: its title `{CVE} ({Severity}) detected in {lib}` embeds a severity word that Mend moves on
every rescore, so an exact match orphans the work item exactly as the count and score did. The key
is the CVE and the library together -- CVE alone collides when one CVE hits two libraries in a
project, and library alone is dependency mode.
"""

import re

# The shipped dependency-mode vulnerability title is
#     f"{lib_name}: {len(relevant_vuls)} vulnerabilities (highest severity is {max_severity})"
# Everything after the library name is a wildcard, so the count and score can change freely without
# changing which work item the title identifies. max_severity is "" when Mend has not scored
# anything, so the score group must tolerate empty.
_TITLE_SUFFIX = re.compile(r": \d+ vulnerabilities \(highest severity is .*\)$")

# The same format as one anchored whole-title pattern, used to DECODE a title whose library name
# is not known in advance. The library group is greedy and may itself contain ":" -- Maven
# coordinates are "{group}:{artifact}" (org.apache:log4j), so splitting on the first colon and
# guessing the head decoded nothing for a large share of Java projects, and those work items
# could be created and updated but never closed.
_DEPENDENCY_TITLE = re.compile(
    r"(?P<lib>.+): \d+ vulnerabilities \(highest severity is .*\)")


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


def parse_dependency_title(title: str):
    """A dependency-mode vulnerability title -> its library name, or None when it is not one.

    The inverse of matches_library for the case where the library is unknown: the whole title is
    matched against the anchored format rather than a prefix being guessed. A title that is not
    exactly the generated format returns None, so a person's hand-written work item is never
    adopted.
    """
    match = _DEPENDENCY_TITLE.fullmatch((title or "").strip())
    if not match:
        return None
    lib = match.group("lib").strip()
    return lib or None


def license_title(lib_name: str) -> str:
    """Unchanged from the shipped format -- matched exactly, so it must stay byte-identical."""
    return f"License Policy Violation detected in {(lib_name or '').strip()}"


# The per-CVE (MEND_DEPENDENCY=false) title is
#     f"{vul_name} ({severity}) detected in {library}"
# `severity` is a wildcard for the same reason the dependency-mode count and score are: Mend
# rescores a CVE and the word changes, while the work item is still the same work item. It may be
# empty ("()") when the finding carries no severity.
#
# The CVE group is deliberately NOT ".+": it must contain a hyphen and no whitespace or brackets,
# which every Mend vulnerability identifier does (CVE-2021-44228, WS-2019-0379, GHSA-jfh8-c2jp).
# Without that, a hand-written title like "Investigate deploy (urgent) detected in prod" would be
# adopted by this tool and closed -- the one thing classify_title must never do.
_CVE_TITLE = re.compile(
    r"(?P<cve>[^\s()]+-[^\s()]+) \((?P<severity>[^()]*)\) detected in (?P<library>.+)")


def parse_cve_title(title: str):
    """A per-CVE title -> (cve, library), or None when it is not one.

    `library` takes the whole remainder, so a library name that itself contains " detected in "
    still resolves in full.
    """
    match = _CVE_TITLE.fullmatch((title or "").strip())
    if not match:
        return None
    library = match.group("library").strip()
    return (match.group("cve"), library) if library else None


def cve_key(cve: str, lib_name: str) -> str:
    """The per-CVE half of the identity key: "{cve}|{library}".

    Both halves are present on purpose. Keying on the CVE alone collides whenever one CVE affects
    two libraries in one project (common); keying on the library alone is dependency mode and would
    collapse every CVE of a library onto one work item.
    """
    return f"{(cve or '').strip()}|{(lib_name or '').strip()}"


def matches_cve(title: str, cve: str, lib_name: str) -> bool:
    """True when `title` is the per-CVE work item title for this CVE in this library, whatever
    severity word it was last written with. Both sides are compared literally, never as patterns."""
    parsed = parse_cve_title(title)
    if not parsed:
        return False
    return cve_key(*parsed) == cve_key(cve, lib_name)
