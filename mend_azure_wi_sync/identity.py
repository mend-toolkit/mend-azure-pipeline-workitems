"""Work item identity: the key a work item is matched on.

Pure module -- no I/O, no globals beyond the compiled regexes, no Config.

A work item is matched on a key derived from its title. The parts of a title that Mend can change
(the vulnerability count, the highest-severity score, the severity word) are wildcards in the key.
The key is the library name in MEND_DEPENDENCY=true mode and "{cve}|{library}" in per-CVE mode.

License titles are matched exactly, so license_title must stay byte-identical.

A title matching none of the known formats is never adopted, so a hand-written work item that
happens to carry a Mend tag is never treated as one of ours.
"""

import re

# Matches the tail of the dependency-mode vulnerability title
#     f"{lib_name}: {N} vulnerabilities (highest severity is {max_severity})"
# The count and the score are wildcards. The score group accepts empty, since max_severity is ""
# when Mend has scored nothing.
_TITLE_SUFFIX = re.compile(r": \d+ vulnerabilities \(highest severity is .*\)$")

# The whole dependency-mode title, anchored, for decoding one whose library name is not known in
# advance. The library group is greedy and may itself contain ":", since Maven coordinates are
# "{group}:{artifact}" (org.apache:log4j).
_DEPENDENCY_TITLE = re.compile(
    r"(?P<lib>.+): \d+ vulnerabilities \(highest severity is .*\)")


def matches_library(title: str, lib_name: str) -> bool:
    """True when `title` is the dependency-mode vulnerability work item title for `lib_name`.

    Requires `title` to start with "{lib_name}:" and the remainder to be exactly the generated
    suffix. `lib_name` is compared literally, never as a pattern.
    """
    lib = (lib_name or "").strip()
    if not title or not lib:
        return False
    if not title.startswith(f"{lib}:"):
        return False
    return _TITLE_SUFFIX.fullmatch(title[len(lib):]) is not None


def parse_dependency_title(title: str):
    """A dependency-mode vulnerability title -> its library name, or None if it is not one.

    Matches the whole anchored format, so a title that is not exactly the generated shape returns
    None.
    """
    match = _DEPENDENCY_TITLE.fullmatch((title or "").strip())
    if not match:
        return None
    lib = match.group("lib").strip()
    return lib or None


def license_title(lib_name: str) -> str:
    """The license work item title for `lib_name`. Matched exactly, so this format must stay
    byte-identical."""
    return f"License Policy Violation detected in {(lib_name or '').strip()}"


# Matches the per-CVE (MEND_DEPENDENCY=false) title
#     f"{vul_name} ({severity}) detected in {library}"
# `severity` is a wildcard and may be empty ("()"). The CVE group requires a hyphen and rejects
# whitespace and brackets, which every Mend vulnerability identifier satisfies (CVE-2021-44228,
# WS-2019-0379, GHSA-jfh8-c2jp).
_CVE_TITLE = re.compile(
    r"(?P<cve>[^\s()]+-[^\s()]+) \((?P<severity>[^()]*)\) detected in (?P<library>.+)")


def parse_cve_title(title: str):
    """A per-CVE title -> (cve, library), or None when it is not one.

    `library` takes the whole remainder, so a library name that itself contains " detected in "
    resolves in full.
    """
    match = _CVE_TITLE.fullmatch((title or "").strip())
    if not match:
        return None
    library = match.group("library").strip()
    return (match.group("cve"), library) if library else None


def cve_key(cve: str, lib_name: str) -> str:
    """The per-CVE half of the identity key: "{cve}|{library}"."""
    return f"{(cve or '').strip()}|{(lib_name or '').strip()}"


def matches_cve(title: str, cve: str, lib_name: str) -> bool:
    """True when `title` is the per-CVE work item title for this CVE in this library, whatever
    severity word it carries. Both sides are compared literally, never as patterns."""
    parsed = parse_cve_title(title)
    if not parsed:
        return False
    return cve_key(*parsed) == cve_key(cve, lib_name)
