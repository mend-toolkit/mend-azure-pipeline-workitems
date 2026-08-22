"""Normalise Mend API 3.0 payloads into the shapes reconciliation consumes.

Pure module -- no I/O, no globals, no Config. All HTTP lives in core.py. Same split as
routing.py and enrichment.py.

This separation is deliberate and load-bearing beyond tidiness: the spec shelves a future 1.4
compatibility path for customers not yet on 3.0. Reconciliation consumes the normalised shapes
defined here and must never reach into a 3.0 response, so that path is a second producer rather
than a rewrite.
"""

import os
import sys

sys.path.append(os.path.dirname(__file__))
from enrichment import format_epss, format_exploit, format_reachability

# CVSS v3 band floors. A band names the BOTTOM of its range, so "high" selects 7.0 and up.
_BANDS = {"low": 0.1, "medium": 4.0, "high": 7.0, "critical": 9.0}

DEFAULT_FLOOR = 7.0


def severity_floor(raw) -> float:
    """MEND_SEVERITY -> the minimum CVSS score that earns a work item.

    Anything unparseable falls back to DEFAULT_FLOOR rather than to 0. A typo must not silently
    turn a high-severity filter into "every finding in the org", which at this customer's scale
    is tens of thousands of work items.
    """
    text = str(raw or "").strip().lower()
    if not text:
        return DEFAULT_FLOOR
    if text in _BANDS:
        return _BANDS[text]
    try:
        value = float(text)
    except (TypeError, ValueError):
        return DEFAULT_FLOOR
    return value if 0.0 <= value <= 10.0 else DEFAULT_FLOOR


def meets_threshold(score, floor: float) -> bool:
    """Is this finding severe enough to hold a work item open?

    An UNSCORED finding is included, deliberately (spec 5.1): it cannot be compared, and a real
    vulnerability disappearing because Mend has not scored it yet is worse than one extra work
    item. `None` and "" mean unscored; 0.0 is a real score and is compared normally.
    """
    if score is None or score == "":
        return True
    try:
        return float(score) >= floor
    except (TypeError, ValueError):
        # A score we cannot read is not a score that lets us exclude anything.
        return True


# The ONLY status that holds a work item open. Every other value in
# SecurityFindingDTOV3.findingInfo.status -- IGNORED (suppressed in Mend), LIBRARY_REMOVED,
# LIBRARY_IN_HOUSE, LIBRARY_WHITELIST -- means the work item should be closed.
#
# This single field is why v3 can close work items and 1.4 never could: 1.4 published no status,
# so closure there had to be inferred from a finding's ABSENCE, and absence is indistinguishable
# from a failed read.
#
# findingInfo.status is marked "deprecated": true in the 3.0 spec (title: "Deprecated Finding
# Status") -- confirmed by inspecting references/3.0 (2).json directly. It is used anyway because
# it is the ONLY field that expresses LIBRARY_REMOVED, which is what makes closure possible at
# all. The non-deprecated replacement, findingInfo.findingStatus, is NOT a drop-in: its enum is
# UNREVIEWED | IN_REVIEW | SUPPRESSED | ISSUE_CREATED | REMEDIATED -- a review-workflow state, not
# a library-presence state -- and has no value that means "the library is gone". Do not switch to
# it without first confirming, live, how a removed library is represented there (if at all).
OPEN_STATUS = "ACTIVE"


def _walk(obj, *path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def normalise_findings(findings, floor: float):
    """3.0 security findings -> ({library_name: entry}, unscored_count).

    Only ACTIVE findings at or above `floor` survive. findingInfo.findingStatus is deliberately
    NOT consulted -- see OPEN_STATUS.

    A library whose findings are all excluded produces NO entry, which is what tells
    reconciliation to close its work item. An entry with an empty findings list would keep the
    item open forever, so entries are only created when something survives.
    """
    entries = {}
    unscored = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        if _walk(finding, "findingInfo", "status") != OPEN_STATUS:
            continue
        lib = _walk(finding, "component", "name")
        if not lib:
            continue
        score = _walk(finding, "vulnerability", "score")
        if not meets_threshold(score, floor):
            continue
        if score is None or score == "":
            unscored += 1
        entry = entries.setdefault(lib, {"library": lib, "kind": "vulnerability", "findings": []})
        entry["findings"].append(finding)
    return entries, unscored


# Licenses are policy-driven: a license is a VIOLATION because a policy says so, which is why
# they keep coming from /violations rather than from a severity threshold.
LEGAL_FINDING_TYPE = "LEGAL"


def normalise_violations(violations):
    """3.0 project violations -> {library_name: entry} for license work items.

    ASYMMETRY WORTH KNOWING: ProjectViolationDTOV3 carries NO status field, unlike a security
    finding. So a license work item is closed by its violation being ABSENT from this list, while
    a vulnerability work item is closed by an explicit status. This assumes /violations returns
    only CURRENT violations -- spec gate G3, unverified against a live org. If it also returns
    resolved ones, license work items will never close and this function needs a filter it
    currently has no field to apply.
    """
    entries = {}
    for violation in violations or []:
        if not isinstance(violation, dict):
            continue
        if violation.get("findingType") != LEGAL_FINDING_TYPE:
            continue
        lib = violation.get("originName")
        if not lib:
            continue
        entry = entries.setdefault(lib, {"library": lib, "kind": "license", "findings": []})
        entry["findings"].append(violation)
    return entries


def normalise_projects(rows):
    """ProjectSummaryDTOV3 rows -> the project shape the rest of the tool uses.

    `tags` becomes {key: [values]} -- the same shape the 1.4 getOrganizationProjectTags sweep
    produced, which is why routing.py needs no change. Joshua confirmed live that 3.0 tags ARE
    the 1.4 project tags, not a different object.

    A repeated tag key keeps every value rather than collapsing to one: a multi-valued routing
    tag is a real misconfiguration that routing.py already detects and reports, and silently
    picking one here would hide it.
    """
    projects = []
    for row in rows or []:
        if not isinstance(row, dict) or not row.get("uuid"):
            continue
        tags = {}
        for tag in row.get("tags") or []:
            if not isinstance(tag, dict):
                continue
            # EntityTagDTO (spec) has exactly two properties: key and value -- there is no
            # "name". `name` is accepted second only for tolerance; `key` is authoritative.
            key = tag.get("key") or tag.get("name")
            if not key:
                continue
            tags.setdefault(key, []).append(tag.get("value"))
        projects.append({
            "uuid": row.get("uuid"),
            "name": row.get("name") or "",
            "application_uuid": row.get("applicationUuid") or "",
            "application_name": row.get("applicationName") or "",
            "last_scanned": row.get("lastScanned") or "",
            "tags": tags,
        })
    return projects


def select_projects(projects, include_uuids, exclude_uuids):
    """Apply MEND_PRODUCTTOKEN / MEND_PROJECTTOKEN / MEND_EXCLUDETOKEN, all now 3.0 UUIDs.

    Returns (selected, unresolved). `unresolved` is every configured UUID that matched no project
    or application, and the caller MUST abort the run on a non-empty list. Selecting nothing
    silently would read as "no work to do", and under reconciliation that closes every work item
    in scope -- the single most destructive failure this tool has available.
    """
    include = [u for u in (include_uuids or []) if u]
    exclude = [u for u in (exclude_uuids or []) if u]
    known = set()
    for project in projects:
        known.add(project["uuid"])
        if project["application_uuid"]:
            known.add(project["application_uuid"])
    unresolved = [u for u in include + exclude if u not in known]

    include_set, exclude_set = set(include), set(exclude)
    selected = []
    for project in projects:
        keys = {project["uuid"], project["application_uuid"]}
        if include_set and not (keys & include_set):
            continue
        if keys & exclude_set:
            continue
        selected.append(project)
    return selected, unresolved


def _dependency_type(component: dict, finding: dict) -> str:
    """component.dependencyType wins; otherwise fall back to the first dependencyContexts
    entry's isDirect flag. Neither present -> "" (the caller renders that as unknown, not
    as a guess)."""
    dep_type = component.get("dependencyType")
    if dep_type:
        return dep_type
    contexts = finding.get("dependencyContexts")
    if isinstance(contexts, list) and contexts and isinstance(contexts[0], dict):
        is_direct = contexts[0].get("isDirect")
        if is_direct is True:
            return "Direct"
        if is_direct is False:
            return "Transitive"
    return ""


def _parents(findings: list) -> list:
    """Every dependencyContexts[].directRoots[] entry across all findings for this library,
    rendered as "name@version" and deduped in first-seen order."""
    parents = []
    seen = set()
    for finding in findings:
        contexts = finding.get("dependencyContexts")
        if not isinstance(contexts, list):
            continue
        for context in contexts:
            if not isinstance(context, dict):
                continue
            roots = context.get("directRoots")
            if not isinstance(roots, list):
                continue
            for root in roots:
                if not isinstance(root, dict):
                    continue
                label = f"{root.get('rootLibraryName') or ''}@{root.get('rootLibraryVersion') or ''}"
                if label not in seen:
                    seen.add(label)
                    parents.append(label)
    return parents


def _vulnerability_row(finding: dict) -> dict:
    """One finding -> the flat vulnerability row the CVE table renders.

    format_epss/format_exploit expect vulnerability.threatAssessment.*, and
    format_reachability expects a top-level "reachability" key -- both shaped after the 1.4
    policy element they were written for. A 3.0 finding carries threatAssessment and
    reachability top-level instead, so a small shim dict is built to match rather than
    reshaping those formatters (they encode hard-won EPSS/maturity/reachability display
    rules that must not be re-derived here).
    """
    vuln = finding.get("vulnerability")
    vuln = vuln if isinstance(vuln, dict) else {}
    top_fix = finding.get("topFix")
    top_fix = top_fix if isinstance(top_fix, dict) else {}
    refs = vuln.get("references")
    first_ref = refs[0] if isinstance(refs, list) and refs and isinstance(refs[0], dict) else {}

    shim = {
        "reachability": finding.get("reachability"),
        "vulnerability": {"threatAssessment": finding.get("threatAssessment")},
    }

    raw_score = vuln.get("score")
    return {
        "name": vuln.get("name") or "",
        "score": raw_score if raw_score is not None and raw_score != "" else "",
        "severity": vuln.get("severity") or "",
        "description": vuln.get("description") or "",
        "url": first_ref.get("url") or "",
        "epss": format_epss(shim),
        "maturity": format_exploit(shim),
        "reachability": format_reachability(shim),
        "fix_resolution": top_fix.get("fixResolution") or "",
        "fix_type": top_fix.get("type") or "",
        "fix_url": top_fix.get("url") or "",
        "publish_date": vuln.get("publishDate") or "",
    }


def _vulnerabilities(findings: list) -> list:
    """One row per finding, sorted by score descending with unscored findings last.

    An operator scans this table top-down, so the most severe, comparable finding must lead.
    0.0 is a real score (sorts normally); None/"" is unscored and always sorts after every
    scored row, regardless of value.
    """
    rows = [_vulnerability_row(f) for f in findings]

    def sort_key(row):
        score = row["score"]
        if score == "":
            return (1, 0.0)
        try:
            return (0, -float(score))
        except (TypeError, ValueError):
            return (1, 0.0)

    rows.sort(key=sort_key)
    return rows


def render_inputs(entry: dict) -> dict:
    """One `desired` entry ({"library", "kind", "findings"}) -> the flat inputs the HTML
    description builders consume.

    Never raises: every missing or malformed key yields "" or [], not None. A `kind ==
    "license"` entry carries violation objects, not findings -- those have no
    component/vulnerability to read, so it returns just the library name with everything
    else empty. Task 2 attaches license data separately.
    """
    library = entry.get("library") if isinstance(entry, dict) else ""
    result = {
        "library": library or "",
        "version": "",
        "description": "",
        "home_page": "",
        "dependency_type": "",
        "dependency_file": "",
        "library_path": "",
        "parents": [],
        "vulnerabilities": [],
    }
    if not isinstance(entry, dict) or entry.get("kind") != "vulnerability":
        return result

    findings = [f for f in (entry.get("findings") or []) if isinstance(f, dict)]
    if not findings:
        return result

    component = _walk(findings[0], "component")
    component = component if isinstance(component, dict) else {}
    references = component.get("references")
    references = references if isinstance(references, dict) else {}
    locations = component.get("libraryLocations")
    first_location = locations[0] if isinstance(locations, list) and locations and isinstance(locations[0], dict) \
        else {}

    result["version"] = component.get("version") or ""
    result["description"] = component.get("description") or ""
    result["home_page"] = references.get("homePage") or ""
    result["dependency_type"] = _dependency_type(component, findings[0])
    result["dependency_file"] = component.get("dependencyFile") or first_location.get("dependencyFile") or ""
    result["library_path"] = component.get("localPath") or component.get("path") or first_location.get(
        "localPath") or ""
    result["parents"] = _parents(findings)
    result["vulnerabilities"] = _vulnerabilities(findings)
    return result
