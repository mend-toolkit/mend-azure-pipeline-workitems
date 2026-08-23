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
from identity import cve_key

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


def _clean_root_name(value) -> str:
    """A rootLibraryName as it can safely be used as a grouping key, or "".

    STRIPPED, because this name becomes the `desired` key AND the work item title, and
    identity.classify_title strips what it decodes: 'express-4.16.4.tgz ' never matches the item
    it just created, so the item is created fresh every run AND closed every run. '  ' is no name
    at all and must not become a work item.

    COERCED, because Mend gives no schema guarantee here and sorted() over a mixed str/int set
    raises TypeError -- which sync_project_v3 catches as a WHOLE-PROJECT failure. Every other
    normaliser in this module skips a malformed row instead, and so does this one: a number is
    coerced (it is still a usable identity), anything else is dropped.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def root_names(finding: dict) -> list:
    """Every distinct root library a finding is reachable from, sorted.

    A ROOT is a direct dependency of the project -- the thing an operator can actually change. A
    transitive library reachable from three roots yields three names, and the finding is filed under
    each: whoever owns express needs to see everything upgrading express would fix, and so does
    whoever owns webpack.

    Read from dependencyContexts[].directRoots[] (DirectRootDTOV3), which is ALREADY in the
    findings response -- the grouping costs no extra call. Several contexts can each carry roots:
    body-parser-1.18.3.tgz is both a DIRECT dependency (root = itself) and TRANSITIVE via express,
    and both are real.

    A finding with no usable context falls back to its own component name, so it becomes its own
    root rather than vanishing: a work item that should exist and does not is strictly worse than
    one filed under the library itself. Returns [] only when there is no name to use at all.

    Sorted, not first-seen: first-seen is Mend's API order, which is not stable between runs, and
    an unstable grouping rewrites every work item in the project when it reshuffles.
    """
    names = set()
    if isinstance(finding, dict):
        contexts = finding.get("dependencyContexts")
        if isinstance(contexts, list):
            for context in contexts:
                if not isinstance(context, dict):
                    continue
                roots = context.get("directRoots")
                if not isinstance(roots, list):
                    continue
                for root in roots:
                    if isinstance(root, dict):
                        name = _clean_root_name(root.get("rootLibraryName"))
                        if name:
                            names.add(name)
    if names:
        return sorted(names)
    own = _clean_root_name(_walk(finding, "component", "name")) if isinstance(finding, dict) else ""
    return [own] if own else []


def _finding_sort_key(finding):
    """A total, meaningful order over an entry's findings: (library name, CVE name).

    Mend returns findings in response order, which is NOT stable between runs. Under root
    grouping an entry holds findings for MANY libraries, and three separate consumers read that
    order: render_inputs (the header's component), library_url (the Hyperlink relation) and
    core.mend_val (MEND:findings.* custom fields, which resolve against the LAST finding).
    A reshuffle therefore changed the rendered description, wi_content_diff saw a change, and the
    item was PATCHed on every run -- dragging operator-set states back to New. That is the
    spurious-rewrite bug 5c53f8a fixed, reintroduced by grouping.

    Missing or non-string keys sort as "" rather than raising: nothing on this path may fail on
    malformed Mend data.
    """
    library = _walk(finding, "component", "name") if isinstance(finding, dict) else None
    cve = _walk(finding, "vulnerability", "name") if isinstance(finding, dict) else None
    return (library if isinstance(library, str) else "",
            cve if isinstance(cve, str) else "")


def _with_sorted_findings(entries: dict) -> dict:
    """Put every entry's findings in _finding_sort_key order, in place, and return the entries.

    Applied in BOTH grouping modes. In per-CVE mode an entry's findings all share one library and
    one CVE, so the sort is a stable no-op there.
    """
    for entry in entries.values():
        entry["findings"].sort(key=_finding_sort_key)
    return entries


def normalise_findings(findings, floor: float, per_cve: bool = False):
    """3.0 security findings -> ({identity_key: entry}, unscored_count).

    Only ACTIVE findings at or above `floor` survive. findingInfo.findingStatus is deliberately
    NOT consulted -- see OPEN_STATUS.

    A key whose findings are all excluded produces NO entry, which is what tells reconciliation to
    close its work item. An entry with an empty findings list would keep the item open forever, so
    entries are only created when something survives.

    `per_cve` is MEND_DEPENDENCY=false and it changes the GROUPING, because in that mode one work
    item is one CVE rather than one library, and the key must be the work item's identity or
    reconciliation cannot find it:
      - False -> key is the ROOT LIBRARY name (see root_names); every finding reachable from that
                 root shares one entry, and a finding with several roots appears under each.
      - True  -> key is "{cve}|{library}" (identity.cve_key); one entry per CVE per library. Both
                 halves are in the key: the CVE alone collides when one CVE hits two libraries in
                 a project, the library alone is dependency mode.
    Every entry carries "library" either way, so callers never have to take it apart again.

    The flag is a PARAMETER, not a Config read: this module is pure, and conf is read in
    core.fetch_v3_desired and threaded down.

    In per-CVE mode a finding with no vulnerability name is dropped: the renderer skips it (there
    is no title to build), so keeping it would put an entry in `desired` that no work item can
    ever satisfy.
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
            # Counted once per FINDING, not once per root: this tally is a project-level report.
            unscored += 1
        if per_cve:
            cve = _walk(finding, "vulnerability", "name")
            if not cve:
                continue
            entry = entries.setdefault(cve_key(cve, lib),
                                       {"library": lib, "kind": "vulnerability", "findings": []})
            entry["findings"].append(finding)
            continue
        # Dependency mode groups by ROOT library. One finding reachable from several roots is
        # filed under each -- see root_names.
        for root in root_names(finding):
            entry = entries.setdefault(root, {"library": root, "kind": "vulnerability",
                                              "findings": []})
            entry["findings"].append(finding)
    return _with_sorted_findings(entries), unscored


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


def normalise_licenses(rows) -> dict:
    """3.0 due-diligence rows (GET .../dependencies/libraries/licenses) -> {library_name:
    [{"name", "url", "reference_file"}, ...]}.

    Schema, read from references/3.0 (2).json (do not re-derive from memory -- see Task 2
    brief): the 200 response is DWRResponsePageableV3ListDueDiligenceDTOV3, whose "response"
    array holds DueDiligenceDTOV3. Each row is ONE library/license pairing, not a library with
    a licenses array, so grouping into a list happens here:
      - DueDiligenceDTOV3.component.name  -- the library name (LibraryComponentDTOV3.name)
      - DueDiligenceDTOV3.name            -- the license name (e.g. "MIT")
      - DueDiligenceDTOV3.license         -- $ref LicenseReferenceDTO:
          - license.textUrl            -- URL to the license text -> "url"
          - license.liabilityReference -- URL/path to the artifact that evidenced the license
                                           (e.g. a pom.xml) -> "reference_file"

    A row missing a library name is skipped, as is anything that isn't a dict. `None`/garbage
    input (not a list) returns {} rather than raising.
    """
    index = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        lib = _walk(row, "component", "name")
        if not lib:
            continue
        index.setdefault(lib, []).append({
            "name": row.get("name") or "",
            "url": _walk(row, "license", "textUrl") or "",
            "reference_file": _walk(row, "license", "liabilityReference") or "",
        })
    return index


# The library metadata a license work item needs, and the due-diligence field each one comes
# from. ProjectViolationDTOV3 -- what a license entry's findings are -- carries NO component at
# all, so a license work item has no other source for these: without this index its rendered
# description shows an empty "Path to dependency file", "Path to library" and "Library home
# page". The rows are the SAME ones normalise_licenses reads, so this costs no extra API call.
def normalise_library_components(rows) -> dict:
    """3.0 due-diligence rows -> {library_name: {version, description, dependency_type,
    dependency_file, library_path, home_page}}.

    Schema (references/3.0 (2).json): DueDiligenceDTOV3.component is a LibraryComponentDTOV3,
    which carries version, description, dependencyType, dependencyFile, localPath and path, plus
    references.homePage via ComponentReferencesDTO. DueDiligenceDTOV3.extraData.homepage
    (ResourceExtraDataDTO) is a second home-page source and is accepted as a fallback.

    One library appears once PER LICENSE it carries, so the same component arrives repeatedly.
    First non-empty value wins per field: a sparse row must not blank out what a fuller row for
    the same library already supplied.

    Missing library name, missing/malformed component, non-dict row, `None` input -- all yield
    nothing rather than raising. Every value is a string, never None, so the renderer can test it
    for emptiness directly.
    """
    index = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        component = row.get("component")
        component = component if isinstance(component, dict) else {}
        lib = component.get("name")
        if not lib:
            continue
        references = component.get("references")
        references = references if isinstance(references, dict) else {}
        found = {
            "version": component.get("version") or "",
            "description": component.get("description") or "",
            "dependency_type": component.get("dependencyType") or "",
            "dependency_file": component.get("dependencyFile") or "",
            "library_path": component.get("localPath") or component.get("path") or "",
            "home_page": references.get("homePage") or _walk(row, "extraData", "homepage") or "",
            # The library's page in Mend. Two jobs: the work item's Hyperlink relation (which a
            # license entry otherwise has no source for -- see library_url) and the License
            # Details link when Mend publishes no license text URL.
            "mend_url": references.get("url") or references.get("homePage") or "",
        }
        current = index.setdefault(lib, dict.fromkeys(found, ""))
        for key, value in found.items():
            if value and not current[key]:
                current[key] = value
    return index


# The 1.4-EQUIVALENT source for the same six fields, and the primary one.
#
# 1.4 read these from a dedicated per-project call, getProjectLibraryLocations, keyed by library
# keyUuid and consulted for EVERY work item -- license or CVE -- because the index was keyed by
# library and never looked at the violation (core.get_pathes, deleted in 9957482):
#
#     locations[0]['dependencyFile'], locations[0]['path']
#
# GET /projects/{uuid}/dependencies/libraries -> LibraryDTOV3 is that call's 3.0 counterpart and
# carries the same shapes: locations[] (LibraryLocationDTO: localPath + dependencyFile) and
# licenses[].licenseReferences[] (a LIST, exactly as 1.4's licenses[].references[] was). Due
# diligence projects each of those down to a single nullable scalar, which is why it is the
# fallback here and not the primary.
def normalise_libraries(rows) -> dict:
    """3.0 project libraries -> {library_name: {version, description, dependency_type,
    dependency_file, library_path, home_page}} -- the same shape
    normalise_library_components returns, so the two are mergeable.

    Paths come from the FIRST location that carries each value, not from locations[0]
    positionally as 1.4 did: a leading location with neither field is a hole, and reading it
    positionally renders as a blank line when the project does know the path.

    home_page is extraInformation.homePage (LibraryExtraInfoDTO) -- the counterpart of the
    references.url that 1.4 read off getProjectLicenses.
    """
    index = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        lib = row.get("name")
        if not lib:
            continue
        dependency_file, library_path = "", ""
        for location in row.get("locations") or []:
            if not isinstance(location, dict):
                continue
            dependency_file = dependency_file or (location.get("dependencyFile") or "")
            library_path = library_path or (location.get("localPath") or "")
        extra = row.get("extraInformation")
        extra = extra if isinstance(extra, dict) else {}
        found = {
            "version": row.get("version") or "",
            "description": row.get("description") or "",
            "dependency_type": row.get("dependencyType") or _direct_flag(row),
            "dependency_file": dependency_file,
            "library_path": library_path,
            "home_page": extra.get("homePage") or "",
            # LibraryDTOV3 has no ComponentReferencesDTO, so it cannot supply the Mend library
            # page -- the key is present and empty so the due-diligence index can fill it.
            "mend_url": "",
        }
        current = index.setdefault(lib, dict.fromkeys(found, ""))
        for key, value in found.items():
            if value and not current[key]:
                current[key] = value
    return index


def _direct_flag(row: dict) -> str:
    """LibraryDTOV3.directDependency -> the word the description renders. "" when absent, which
    the caller shows as unknown rather than guessing "Direct"."""
    is_direct = row.get("directDependency")
    if is_direct is True:
        return "Direct"
    if is_direct is False:
        return "Transitive"
    return ""


def normalise_library_licenses(rows) -> dict:
    """3.0 project libraries -> {library_name: [{"name", "url", "reference_file"}, ...]}, the
    same shape normalise_licenses returns off the due-diligence rows.

    LibraryDTOV3.licenses[] is a LibraryLicenseDTOV3, whose licenseReferences[] is a LIST of
    LicenseReferenceDTO -- the same shape 1.4's licenses[].references[] had, which is what
    populated "License Reference File" before. The first reference carrying each value wins, so
    a leading reference with no liabilityReference does not blank the line.

    extraInformation.licenseUrl (LibraryExtraInfoDTO) is the closest reachable analogue of 1.4's
    licenses[].url and fills `url` when a license publishes no textUrl of its own. It is
    per-LIBRARY, not per-license, so it is attributed ONLY when the library carries exactly one
    license: handing one URL to two different licenses asserts something Mend never said. A
    multi-license library falls through to the library's Mend page instead -- see
    core.build_license_html_v3.
    """
    index = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        lib = row.get("name")
        if not lib:
            continue
        licences = [lic for lic in (row.get("licenses") or [])
                    if isinstance(lic, dict) and lic.get("name")]
        extra = row.get("extraInformation")
        extra = extra if isinstance(extra, dict) else {}
        library_wide_url = (extra.get("licenseUrl") or "") if len(licences) == 1 else ""
        for licence in licences:
            url, reference = "", ""
            for ref in licence.get("licenseReferences") or []:
                if not isinstance(ref, dict):
                    continue
                url = url or (ref.get("textUrl") or "")
                reference = reference or (ref.get("liabilityReference") or "")
            index.setdefault(lib, []).append({
                "name": licence["name"],
                "url": url or library_wide_url,
                "reference_file": reference,
            })
    return index


def merge_component_index(primary: dict, fallback: dict) -> dict:
    """Union two component indexes field by field: primary wins wherever it has a value, the
    fallback fills only its blanks, and a library only the fallback knows about is kept.

    Neither source is complete on its own -- the libraries call is the 1.4-equivalent shape, due
    diligence sometimes carries a field it leaves empty -- and dropping a library the fallback
    alone knows about would put back the empty lines this exists to fix.
    """
    merged = {lib: dict(fields) for lib, fields in (primary or {}).items()
              if isinstance(fields, dict)}
    for lib, fields in (fallback or {}).items():
        if not isinstance(fields, dict):
            continue
        if lib not in merged:
            merged[lib] = dict(fields)
            continue
        for key, value in fields.items():
            if value and not merged[lib].get(key):
                merged[lib][key] = value
    return merged


def merge_license_index(primary: dict, fallback: dict) -> dict:
    """Union two license indexes BY LICENSE NAME: primary wins per field, the fallback fills
    blanks, and a license only the fallback lists is appended after the primary's.

    Keyed by name rather than by position because the two sources need not order or even agree on
    the set of licenses a library carries, and a license work item's License Details block must
    list every one of them.
    """
    merged = {}
    for lib in set(primary or {}) | set(fallback or {}):
        by_name = {}
        order = []
        for source in ((primary or {}).get(lib) or [], (fallback or {}).get(lib) or []):
            for licence in source:
                if not isinstance(licence, dict):
                    continue
                name = licence.get("name") or ""
                if name not in by_name:
                    by_name[name] = dict(licence)
                    order.append(name)
                    continue
                for key, value in licence.items():
                    if value and not by_name[name].get(key):
                        by_name[name][key] = value
        if order:
            # Sorted, not source order: the two sources' orders both come from the API and are
            # not guaranteed stable, and the License Details block is rendered from this list.
            merged[lib] = [by_name[name] for name in sorted(order)]
    return merged


def license_link_report(licenses: dict, components: dict) -> dict:
    """Which source the License Details link would come from, per "{library}/{license}".

    {"license_url": [...], "library_page": [...], "no_link": [...]} -- the same precedence
    core.build_license_html_v3 applies: the license's own URL (LicenseReferenceDTO.textUrl, or
    LibraryExtraInfoDTO.licenseUrl for a single-license library), then the library's Mend page
    (ComponentReferencesDTO.url), then nothing.

    This exists because every one of those fields is optional in 3.0 and which ones an org
    populates cannot be read off the spec -- it took a round of guessing to learn that. A run
    reports it instead.
    """
    report = {"license_url": [], "library_page": [], "no_link": []}
    for lib, entries in (licenses or {}).items():
        if not isinstance(entries, list):
            continue
        component = (components or {}).get(lib)
        mend_url = component.get("mend_url") if isinstance(component, dict) else ""
        for licence in entries:
            if not isinstance(licence, dict):
                continue
            label = f"{lib}/{licence.get('name') or '?'}"
            if licence.get("url"):
                report["license_url"].append(label)
            elif mend_url:
                report["library_page"].append(label)
            else:
                report["no_link"].append(label)
    return report


def normalise_root_libraries(rows) -> dict:
    """3.0 root-library findings -> {root_name: {version, recommended_fix, major_fix, fix_failed,
    severity, total}}.

    Schema (references/3.0 (2).json): RootLibrarySecurityFindingDTOV3, from
    GET /projects/{uuid}/dependencies/findings/security/groupBy/rootLibrary.

    REMEDIATION ONLY. This index never decides which work items exist: `total` INCLUDES suppressed
    findings (body-parser reports 5 live while 2 of its findings are IGNORED) and the endpoint knows
    nothing about MEND_SEVERITY. The item set comes from surviving findings -- see normalise_findings
    -- and `total` is kept for logging alone.

    `recommended_fix` frequently EQUALS `version`, which means "no fix inside the current major";
    interpreting that pair is root_remediation's job, not this function's.
    """
    index = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = row.get("rootLibraryName")
        if not name:
            continue
        index[name] = {
            "version": row.get("rootLibraryVersion") or "",
            "recommended_fix": row.get("recommendedFix") or "",
            "major_fix": row.get("fixForMajorVersion") or "",
            "fix_failed": bool(row.get("suggestedFixFailed")),
            "severity": row.get("severity") or "",
            "total": try_or_error_int(row.get("total")),
        }
    return index


def root_remediation(entry) -> dict:
    """A root index entry -> {"fix", "major", "note"}, the words the work item shows.

    Four states, because recommendedFix frequently EQUALS the installed version and that means
    "no fix inside the current major" rather than "upgrade to what you already have":

      recommendedFix differs, major present -> "4.22.2"                / "5.2.1"
      recommendedFix differs, no major      -> "1.19.0"                / ""
      recommendedFix equals,  major present -> "none available in 2.x" / "4.0.3"
      recommendedFix equals,  no major      -> "none available"        / ""

    Six of ten roots in the sampled project were in the bottom two states, so they are the common
    case, not the edge.

    An EMPTY entry returns all-empty rather than "none available": a root missing from the index is
    a read we did not make, and claiming "no fix available" would assert something we never saw.
    The renderer omits empty lines.

    suggestedFixFailed becomes a note -- "Mend tried and could not" is a different fact from "there
    is nothing to do".

    Mend does not publish which CVEs a root version fixes (spec: "The API limitation"), so nothing
    here may be phrased as per-CVE coverage.
    """
    if not isinstance(entry, dict) or not entry:
        return {"fix": "", "major": "", "note": ""}
    version = str(entry.get("version") or "").strip()
    recommended = str(entry.get("recommended_fix") or "").strip()
    major = str(entry.get("major_fix") or "").strip()

    if recommended and recommended != version:
        # recommended differs from version: use the recommended fix
        fix = recommended
    elif not recommended:
        # recommended is empty/missing: treat as no fix
        fix = "none available"
    else:
        # recommended equals version: check for major fix to qualify the message
        if major:
            series = version.split(".")[0].strip() if version else ""
            # Only a numeric leading component names a series; anything else prints no guess.
            fix = f"none available in {series}.x" if series.isdigit() else "none available"
        else:
            fix = "none available"

    note = "Mend could not compute a fix for this library." if entry.get("fix_failed") else ""
    return {"fix": fix, "major": major, "note": note}


def try_or_error_int(value) -> int:
    """An integer or 0. Local to this module because source3 is pure and cannot import core's
    try_or_error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
    rendered as "name@version", deduped and SORTED.

    Sorted rather than first-seen: first-seen is Mend's API order, which is not guaranteed stable
    between runs, and an unstable list rewrites the work item every time it reshuffles. There is
    no meaningful hierarchy order to preserve here -- these are siblings, all direct roots of the
    same library."""
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
    return sorted(parents)


def _reference_url(vuln: dict) -> str:
    """The CVE link shown in the work item.

    VulnerabilityReferenceDTO carries {value, source, url, signature, advisory, patch}, and the
    list is MIXED -- references[0] is as likely to be a patch commit or a signature as it is the
    advisory. Taking it positionally put patch links in the "URL" column where an operator
    expects the advisory. So: the first reference flagged advisory=true wins, and only if none
    is flagged does the first non-empty url stand in.
    """
    refs = vuln.get("references")
    if not isinstance(refs, list):
        return ""
    candidates = [r for r in refs if isinstance(r, dict) and r.get("url")]
    for ref in candidates:
        if ref.get("advisory") is True:
            return ref["url"]
    return candidates[0]["url"] if candidates else ""


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

    shim = {
        "reachability": finding.get("reachability"),
        "vulnerability": {"threatAssessment": finding.get("threatAssessment")},
    }

    raw_score = vuln.get("score")
    fields = _component_fields(finding)
    return {
        "name": vuln.get("name") or "",
        "score": raw_score if raw_score is not None and raw_score != "" else "",
        "severity": vuln.get("severity") or "",
        "description": vuln.get("description") or "",
        "url": _reference_url(vuln),
        "epss": format_epss(shim),
        "maturity": format_exploit(shim),
        "reachability": format_reachability(shim),
        "fix_resolution": top_fix.get("fixResolution") or "",
        "fix_type": top_fix.get("type") or "",
        "fix_date": top_fix.get("date") or "",
        "fix_url": top_fix.get("url") or "",
        "publish_date": vuln.get("publishDate") or "",
        "library": _walk(finding, "component", "name") or "",
        # The vulnerable library's OWN metadata, per row. Under root grouping the work item
        # header describes the ROOT, so without these every per-CVE <details> section claimed
        # the root was the vulnerable library and showed the root's single path -- eight
        # sections on an eight-library root item all saying the same wrong thing.
        # core.vuln_section_v3 prefers these and falls back to the header's values.
        "dependency_type": fields["dependency_type"],
        "dependency_file": fields["dependency_file"],
        "library_path": fields["library_path"],
    }


def _vulnerabilities(findings: list) -> list:
    """One row per finding, sorted by score descending with unscored findings last.

    An operator scans this table top-down, so the most severe, comparable finding must lead.
    0.0 is a real score (sorts normally); None/"" is unscored and always sorts after every
    scored row, regardless of value.

    The row's `library` is a second tiebreaker, after the CVE name. Under root grouping a single
    work item can hold the SAME CVE for two different library versions (live:
    CVE-2022-25883 on both semver-5.7.0.tgz and semver-5.6.0.tgz, both scored 5.3) -- those two
    rows tie on (band, score, name) too, and without `library` they fall through to whatever
    order the Mend API happened to return them in, which is NOT stable between runs. That is
    exactly the spurious-rewrite bug fixed in 5c53f8a, reintroduced one level up.
    """
    rows = [_vulnerability_row(f) for f in findings]

    def sort_key(row):
        # The CVE name is the primary tiebreaker, and `library` the secondary one -- together they
        # make this deterministic even when two rows share both a CVE and a score. Without them,
        # two such findings keep whatever order the Mend API returned them in, and a reshuffle
        # between runs rewrites every work item in the project for no reason.
        name = row["name"]
        library = row["library"]
        score = row["score"]
        if score == "":
            return (1, 0.0, name, library)
        try:
            return (0, -float(score), name, library)
        except (TypeError, ValueError):
            return (1, 0.0, name, library)

    rows.sort(key=sort_key)
    return rows


def _component_fields(finding: dict) -> dict:
    """One finding's component -> the six header fields, all strings, never None.

    Shared by render_inputs (the work item header) and _vulnerability_row (the per-CVE section's
    own paths), so the two cannot drift. Keys match normalise_library_components' output exactly,
    which is what lets render_inputs choose between a finding and the index field by field.
    """
    component = _walk(finding, "component") if isinstance(finding, dict) else None
    component = component if isinstance(component, dict) else {}
    references = component.get("references")
    references = references if isinstance(references, dict) else {}
    locations = component.get("libraryLocations")
    first_location = locations[0] if isinstance(locations, list) and locations \
        and isinstance(locations[0], dict) else {}
    return {
        "version": component.get("version") or "",
        "description": component.get("description") or "",
        "home_page": references.get("homePage") or "",
        "dependency_type": _dependency_type(component,
                                            finding if isinstance(finding, dict) else {}),
        "dependency_file": component.get("dependencyFile")
        or first_location.get("dependencyFile") or "",
        "library_path": component.get("localPath") or component.get("path")
        or first_location.get("localPath") or "",
    }


def _header_finding(findings: list, library: str):
    """The finding whose component metadata belongs in the work item HEADER.

    The header describes the work item's OWN library -- the root in dependency mode, the
    vulnerable library in per-CVE mode -- so the finding whose component.name equals that
    library is the only correct source. Under root grouping findings[0] is whichever transitive
    library Mend returned first, which is both wrong (a root titled express captioned with qs's
    description and paths) and unstable.

    Returns (finding, matched). `matched` tells render_inputs which source has PRIORITY: when a
    finding really is about the entry's own library its project-specific component wins, exactly
    as it did before grouping; when none is (the normal case for a root, which is usually not
    itself vulnerable) entry["component"] -- the root-keyed due-diligence row -- wins instead,
    and the unmatched findings[0] is only a last resort for fields the index leaves blank.

    In per-CVE mode the match always succeeds, because the entry's library IS its findings'
    component, so behaviour in that mode is unchanged.
    """
    for finding in findings:
        if (_walk(finding, "component", "name") or "") == (library or ""):
            return finding, True
    return (findings[0] if findings else None), False


def render_inputs(entry: dict) -> dict:
    """One `desired` entry ({"library", "kind", "findings"}) -> the flat inputs the HTML
    description builders consume.

    Never raises: every missing or malformed key yields "" or [], not None.

    A `kind == "license"` entry carries ProjectViolationDTOV3 objects, not findings, and that DTO
    has no component -- so its library metadata comes from entry["component"], the index
    normalise_library_components builds from the due-diligence rows and core.fetch_v3_desired
    attaches. `vulnerabilities` and `parents` stay empty for a license entry either way: there is
    no finding to read a CVE or a dependency hierarchy from.

    A VULNERABILITY entry reads its own finding FIRST -- BaseLocationComponentDTOV3 with
    libraryLocations is richer and project-specific, so it stays authoritative -- and falls back
    to entry["component"] only for a field the finding leaves blank. 1.4 rendered these lines
    from a library-keyed location index for every work item, license or CVE, never consulting the
    violation, so a finding with no path of its own must still show the project's.

    WHICH finding supplies that header matters under root grouping, where one entry holds
    findings for MANY libraries: findings[0] captioned a root work item with an arbitrary
    TRANSITIVE library's description and paths, and reshuffled Mend output changed the rendered
    description and rewrote the item on every run. The finding whose component IS the entry's
    library wins; see _header_finding.
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
    if not isinstance(entry, dict):
        return result

    if entry.get("kind") != "vulnerability":
        component = entry.get("component")
        if isinstance(component, dict):
            for key in ("version", "description", "dependency_type", "dependency_file",
                        "library_path", "home_page"):
                result[key] = component.get(key) or ""
            # mend_url is deliberately NOT copied: it is the Hyperlink relation's value (see
            # library_url), not a line in the description.
        return result

    findings = [f for f in (entry.get("findings") or []) if isinstance(f, dict)]
    if not findings:
        return result

    source, matched = _header_finding(findings, library)
    source = source if isinstance(source, dict) else {}
    from_finding = _component_fields(source)

    component_index = entry.get("component")
    from_index = component_index if isinstance(component_index, dict) else {}

    # Priority order. A finding that IS about this library beats the project-wide index (its
    # BaseLocationComponentDTOV3 is richer and project-specific); a finding that is NOT loses to
    # it, because the index row is keyed by the work item's own library and the finding is not.
    sources = (from_finding, from_index) if matched else (from_index, from_finding)
    for key in ("version", "description", "dependency_type", "dependency_file",
                "library_path", "home_page"):
        for candidate in sources:
            value = candidate.get(key) or ""
            if value:
                result[key] = value
                break

    result["parents"] = _parents(findings)
    result["vulnerabilities"] = _vulnerabilities(findings)
    return result


def library_url(entry: dict) -> str:
    """The library's page in Mend, written onto the work item as its Hyperlink relation.

    ComponentReferencesDTO.url is the library page; homePage is the upstream project's own site.
    The first is what an operator wants one click away, so homePage is only a fallback.

    The work item is about ITS OWN library, so the finding whose component is that library wins
    -- not the first finding that happens to carry a URL. Under root grouping an entry holds
    findings for many libraries, and taking the first one pointed a root work item's one-click
    link at an arbitrary transitive library. Next comes entry["component"]["mend_url"], the
    index row keyed by that same library; only then any finding with a URL at all.

    A LICENSE entry has no component at all -- its violations are ProjectViolationDTOV3 -- so it
    reaches the index fallback, the same due-diligence index the description reads. Without that
    fallback a license work item was created with NO Hyperlink relation, which 1.4 always had
    (prj_el["library"]["url"] was in scope for a license violation exactly as for a CVE).

    Returns "" when no source has one, and the caller then writes no relation at all rather
    than an empty one.
    """
    if not isinstance(entry, dict):
        return ""
    library = entry.get("library") or ""

    def url_of(finding):
        references = _walk(finding, "component", "references")
        if isinstance(references, dict):
            return references.get("url") or references.get("homePage") or ""
        return ""

    findings = [f for f in (entry.get("findings") or []) if isinstance(f, dict)]
    for finding in findings:
        if (_walk(finding, "component", "name") or "") == library:
            url = url_of(finding)
            if url:
                return url
    component = entry.get("component")
    if isinstance(component, dict) and component.get("mend_url"):
        return component["mend_url"]
    for finding in findings:
        url = url_of(finding)
        if url:
            return url
    return ""


def license_policy_name(entry: dict) -> str:
    """The policy that a license violation breached, for the "License Policy Violation - " line.

    ProjectViolationDTOV3.name is prefixed with a bracketed tag exactly as the 1.4 policy name
    was (e.g. "[Legal] No GPL"), and the 1.4 path stripped everything up to and including the
    first "]" -- kept identical so the rendered line does not change shape.
    """
    if not isinstance(entry, dict):
        return ""
    for violation in entry.get("findings") or []:
        if not isinstance(violation, dict):
            continue
        name = violation.get("name") or ""
        if name:
            return name[name.find("]") + 1:].strip()
    return ""
