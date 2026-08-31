"""Normalise Mend API 3.0 payloads into the shapes reconciliation consumes.

Pure module -- no I/O, no globals, no Config. All HTTP lives in core.py.

Reconciliation consumes the normalised shapes defined here and never reaches into a 3.0 response
directly.
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

    Accepts a band name (low/medium/high/critical) or a number from 0 to 10. Anything
    unparseable falls back to DEFAULT_FLOOR, never to 0.
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

    An unscored finding is included: `None` and "" mean unscored, while 0.0 is a real score and
    is compared normally.
    """
    if score is None or score == "":
        return True
    try:
        return float(score) >= floor
    except (TypeError, ValueError):
        # An unreadable score does not exclude the finding.
        return True


# The only SecurityFindingDTOV3.findingInfo.status that holds a work item open. Every other value
# -- IGNORED (suppressed in Mend), LIBRARY_REMOVED, LIBRARY_IN_HOUSE, LIBRARY_WHITELIST -- closes
# it.
#
# findingInfo.status is marked "deprecated": true in the 3.0 spec. It is read anyway because it is
# the only field that expresses LIBRARY_REMOVED. findingInfo.findingStatus is NOT a drop-in
# replacement: its enum (UNREVIEWED | IN_REVIEW | SUPPRESSED | ISSUE_CREATED | REMEDIATED) is a
# review-workflow state with no value meaning "the library is gone".
OPEN_STATUS = "ACTIVE"


def _walk(obj, *path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def _clean_root_name(value) -> str:
    """A rootLibraryName as it can safely be used as a grouping key, or "".

    Stripped, because this name becomes both the `desired` key and the work item title, and
    identity.classify_title strips what it decodes. A whitespace-only name yields "".

    A number is coerced to its string form; any other type yields "". Mend gives no schema
    guarantee here, and a mixed str/int set would raise TypeError in sorted().
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

    A root is a direct dependency of the project. A transitive library reachable from three roots
    yields three names, and the finding is filed under each.

    Read from dependencyContexts[].directRoots[] (DirectRootDTOV3), already present in the findings
    response, so grouping costs no extra call. Several contexts can each carry roots, and a library
    can be both a direct dependency (root = itself) and transitive via another.

    A finding with no usable context falls back to its own component name, becoming its own root.
    Returns [] only when there is no name to use at all.

    Sorted, not first-seen: Mend's API order is not stable between runs, and an unstable grouping
    rewrites every work item in the project when it reshuffles.
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

    Mend returns findings in response order, which is not stable between runs. Three consumers
    read this order -- render_inputs (the header's component), library_url (the Hyperlink relation)
    and core.mend_val (MEND:findings.* custom fields, which resolve against the last finding) -- so
    a reshuffle would change the rendered description and rewrite the work item on every run.

    Missing or non-string keys sort as "" rather than raising.
    """
    library = _walk(finding, "component", "name") if isinstance(finding, dict) else None
    cve = _walk(finding, "vulnerability", "name") if isinstance(finding, dict) else None
    return (library if isinstance(library, str) else "",
            cve if isinstance(cve, str) else "")


def _with_sorted_findings(entries: dict) -> dict:
    """Put every entry's findings in _finding_sort_key order, in place, and return the entries.

    Applied in both grouping modes. In per-CVE mode an entry's findings all share one library and
    one CVE, so the sort is a no-op there.
    """
    for entry in entries.values():
        entry["findings"].sort(key=_finding_sort_key)
    return entries


def normalise_findings(findings, floor: float, per_cve: bool = False):
    """3.0 security findings -> ({identity_key: entry}, unscored_count).

    Only findings whose status is OPEN_STATUS and whose score is at or above `floor` survive.
    findingInfo.findingStatus is not consulted -- see OPEN_STATUS.

    A key whose findings are all excluded produces no entry, which is what tells reconciliation to
    close its work item. Entries are only created when something survives, never with an empty
    findings list.

    `per_cve` is MEND_DEPENDENCY=false and selects the grouping, which is the work item's identity
    key:
      - False -> the root library name (see root_names); every finding reachable from that root
                 shares one entry, and a finding with several roots appears under each.
      - True  -> "{cve}|{library}" (identity.cve_key); one entry per CVE per library.
    Every entry carries "library" either way.

    The flag is a parameter rather than a Config read, since this module is pure;
    core.fetch_v3_desired reads conf and threads it down.

    In per-CVE mode a finding with no vulnerability name is dropped, since the renderer has no
    title to build from it.
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
            # Counted once per finding, not once per root: this tally is a project-level report.
            unscored += 1
        if per_cve:
            cve = _walk(finding, "vulnerability", "name")
            if not cve:
                continue
            entry = entries.setdefault(cve_key(cve, lib),
                                       {"library": lib, "kind": "vulnerability", "findings": []})
            entry["findings"].append(finding)
            continue
        # Dependency mode groups by root library. One finding reachable from several roots is
        # filed under each -- see root_names.
        for root in root_names(finding):
            entry = entries.setdefault(root, {"library": root, "kind": "vulnerability",
                                              "findings": []})
            entry["findings"].append(finding)
    return _with_sorted_findings(entries), unscored


# Licenses are policy-driven: a license is a violation because a policy says so, so they come from
# /violations rather than from a severity threshold.
LEGAL_FINDING_TYPE = "LEGAL"


def normalise_violations(violations):
    """3.0 project violations -> {library_name: entry} for license work items.

    ProjectViolationDTOV3 carries no status field, unlike a security finding, so a license work
    item is closed by its violation being absent from this list rather than by an explicit status.
    That relies on /violations returning only current violations; there is no field here to filter
    resolved ones with.
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

    Schema: the 200 response is DWRResponsePageableV3ListDueDiligenceDTOV3, whose "response"
    array holds DueDiligenceDTOV3. Each row is one library/license pairing, not a library with
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


# The library metadata a license work item needs, and the due-diligence field each one comes from.
# ProjectViolationDTOV3 carries no component, so this index is a license work item's only source
# for these fields. The rows are the same ones normalise_licenses reads, so it costs no extra call.
def normalise_library_components(rows) -> dict:
    """3.0 due-diligence rows -> {library_name: {version, description, dependency_type,
    dependency_file, library_path, home_page}}.

    Schema (references/3.0 (2).json): DueDiligenceDTOV3.component is a LibraryComponentDTOV3,
    which carries version, description, dependencyType, dependencyFile, localPath and path, plus
    references.homePage via ComponentReferencesDTO. DueDiligenceDTOV3.extraData.homepage
    (ResourceExtraDataDTO) is a second home-page source and is accepted as a fallback.

    One library appears once per license it carries, so the same component arrives repeatedly and
    the first non-empty value wins per field.

    Missing library name, missing or malformed component, non-dict row and `None` input all yield
    nothing rather than raising. Every value is a string, never None.
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
            # The library's page in Mend. Used for the work item's Hyperlink relation (see
            # library_url) and for the License Details link when Mend publishes no license
            # text URL.
            "mend_url": references.get("url") or references.get("homePage") or "",
            # LibraryComponentDTOV3.uuid -- carried so a later stage can fetch this library's
            # dependency path without a second lookup keyed by name.
            "library_uuid": component.get("uuid") or "",
        }
        current = index.setdefault(lib, dict.fromkeys(found, ""))
        for key, value in found.items():
            if value and not current[key]:
                current[key] = value
    return index


# The primary source for the same six fields, from GET /projects/{uuid}/dependencies/libraries
# -> LibraryDTOV3. It carries locations[] (LibraryLocationDTO: localPath + dependencyFile) and
# licenses[].licenseReferences[] as lists, where the due-diligence rows project each down to a
# single nullable scalar -- which is why due diligence is the fallback and this is the primary.
def normalise_libraries(rows) -> dict:
    """3.0 project libraries -> {library_name: {version, description, dependency_type,
    dependency_file, library_path, home_page}} -- the same shape
    normalise_library_components returns, so the two are mergeable.

    Paths come from the first location that carries each value, not from locations[0]
    positionally: a leading location with neither field would otherwise render as a blank line
    when the project does know the path.

    home_page is extraInformation.homePage (LibraryExtraInfoDTO).
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
            # LibraryDTOV3 has no ComponentReferencesDTO and cannot supply the Mend library
            # page. The key is present and empty so the due-diligence index can fill it.
            "mend_url": "",
            # LibraryDTOV3.uuid -- see normalise_library_components for why this is carried.
            "library_uuid": row.get("uuid") or "",
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

    LibraryDTOV3.licenses[] is a LibraryLicenseDTOV3, whose licenseReferences[] is a list of
    LicenseReferenceDTO. The first reference carrying each value wins, so a leading reference with
    no liabilityReference does not blank the line.

    extraInformation.licenseUrl (LibraryExtraInfoDTO) fills `url` when a license publishes no
    textUrl of its own. It is per-library rather than per-license, so it is attributed only when
    the library carries exactly one license; a multi-license library falls through to the library's
    Mend page instead -- see core.build_license_html_v3.
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


def _path_order(node: dict):
    """A libraryPath node's `order`, or 0 when missing/non-integer -- never raises, never None."""
    try:
        return int(node.get("order"))
    except (TypeError, ValueError):
        return 0


def normalise_library_paths(payload) -> list:
    """The Mend 2.0 dependency-path payload -> [[name, name, ...], ...], root first.

    {"retVal": [{"libraryPath": [{uuid, name, order}, ...]}, ...]}. Each entry's nodes are sorted
    by `order` (stably, so nodes sharing an order keep their arrival sequence) and reduced to
    their names; a node that is not a dict or carries no name is dropped, and a path that ends up
    empty after that filtering is skipped entirely.

    retVal's own order is preserved, never sorted: it is the order Mend presents the paths in.

    Identical chains (same names, same order) are deduped, keeping the first-seen position: two
    retVal entries that reduce to the same chain render as one bullet block, not two.

    A non-dict payload, a missing/non-list `retVal`, or `None` yields [] rather than raising.
    """
    if not isinstance(payload, dict):
        return []
    entries = payload.get("retVal")
    if not isinstance(entries, list):
        return []

    chains = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        library_path = entry.get("libraryPath")
        if not isinstance(library_path, list):
            continue
        nodes = [n for n in library_path if isinstance(n, dict)]
        nodes.sort(key=_path_order)
        names = [n.get("name") for n in nodes if n.get("name")]
        if not names:
            continue
        key = tuple(names)
        if key in seen:
            continue
        seen.add(key)
        chains.append(names)
    return chains


def merge_component_index(primary: dict, fallback: dict) -> dict:
    """Union two component indexes field by field: primary wins wherever it has a value, the
    fallback fills only its blanks, and a library only the fallback knows about is kept.

    Neither source is complete on its own, so a library only the fallback knows about is kept
    rather than dropped.
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

    Keyed by name rather than by position: the two sources need not order, or even agree on, the
    set of licenses a library carries.
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
            # Sorted, not source order: both sources come from the API and are not guaranteed
            # stable, and the License Details block is rendered from this list.
            merged[lib] = [by_name[name] for name in sorted(order)]
    return merged


def license_link_report(licenses: dict, components: dict) -> dict:
    """Which source the License Details link would come from, per "{library}/{license}".

    {"license_url": [...], "library_page": [...], "no_link": [...]} -- the same precedence
    core.build_license_html_v3 applies: the license's own URL (LicenseReferenceDTO.textUrl, or
    LibraryExtraInfoDTO.licenseUrl for a single-license library), then the library's Mend page
    (ComponentReferencesDTO.url), then nothing.

    Every one of those fields is optional in 3.0, and which ones an org populates cannot be read
    off the spec, so a run reports what it actually found.
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

    Schema: RootLibrarySecurityFindingDTOV3, from
    GET /projects/{uuid}/dependencies/findings/security/groupBy/rootLibrary.

    Remediation only. This index never decides which work items exist: `total` includes suppressed
    findings and the endpoint knows nothing about MEND_SEVERITY, so it is kept for logging alone.
    The item set comes from surviving findings -- see normalise_findings.

    `recommended_fix` often equals `version`, which means "no fix inside the current major";
    root_remediation interprets that pair.
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

    Four states, because recommendedFix often equals the installed version, which means "no fix
    inside the current major" rather than "upgrade to what you already have":

      recommendedFix differs, major present -> "4.22.2"                / "5.2.1"
      recommendedFix differs, no major      -> "1.19.0"                / ""
      recommendedFix equals,  major present -> "none available in 2.x" / "4.0.3"
      recommendedFix equals,  no major      -> "none available"        / ""

    An empty entry returns all-empty rather than "none available", since a root missing from the
    index was never read. The renderer omits empty lines.

    suggestedFixFailed becomes a note: "Mend tried and could not" is a different fact from "there
    is nothing to do".

    Mend does not publish which CVEs a root version fixes, so nothing here is phrased as per-CVE
    coverage.
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
    """An integer, or 0 when the value will not convert. Local to this module, which is pure and
    cannot import core's try_or_error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalise_projects(rows):
    """ProjectSummaryDTOV3 rows -> the project shape the rest of the tool uses.

    `tags` becomes {key: [values]}, the shape routing.py consumes.

    A repeated tag key keeps every value rather than collapsing to one, so routing.py can detect
    and report a multi-valued routing tag.
    """
    projects = []
    for row in rows or []:
        if not isinstance(row, dict) or not row.get("uuid"):
            continue
        tags = {}
        for tag in row.get("tags") or []:
            if not isinstance(tag, dict):
                continue
            # EntityTagDTO has exactly two properties, key and value. `key` is authoritative;
            # `name` is accepted second only for tolerance.
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
    or application, and the caller must abort the run on a non-empty list rather than proceed with
    a partial selection.
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

    Sorted rather than first-seen: Mend's API order is not guaranteed stable between runs, and an
    unstable list rewrites the work item every time it reshuffles. These are siblings, all direct
    roots of the same library, so there is no hierarchy order to preserve."""
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

    VulnerabilityReferenceDTO carries {value, source, url, signature, advisory, patch} and the
    list is mixed: references[0] may be a patch commit or a signature rather than the advisory. So
    the first reference flagged advisory=true wins, and only if none is flagged does the first
    non-empty url stand in.
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

    enrichment.format_epss and format_exploit expect vulnerability.threatAssessment.*, and
    format_reachability expects a top-level "reachability" key. A 3.0 finding carries
    threatAssessment and reachability top-level instead, so a shim dict is built to match rather
    than reshaping those formatters.
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
        # The vulnerable library's own metadata, per row. Under root grouping the work item
        # header describes the root, so each per-CVE section needs its own library's fields here.
        # core.vuln_section_v3 prefers these and falls back to the header's values.
        "dependency_type": fields["dependency_type"],
        "dependency_file": fields["dependency_file"],
        "library_path": fields["library_path"],
    }


def _vulnerabilities(findings: list) -> list:
    """One row per finding, sorted by score descending with unscored findings last.

    0.0 is a real score and sorts normally; None and "" are unscored and always sort after every
    scored row, whatever its value.

    The row's `library` is the second tiebreaker, after the CVE name. Under root grouping one work
    item can hold the same CVE for two different library versions, which tie on (band, score, name)
    as well; without `library` those rows would fall through to Mend's API order, which is not
    stable between runs.
    """
    rows = [_vulnerability_row(f) for f in findings]

    def sort_key(row):
        # The CVE name is the primary tiebreaker and `library` the secondary one, which keeps the
        # order deterministic even when two rows share both a CVE and a score.
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
    own paths). Keys match normalise_library_components' output exactly, which lets render_inputs
    choose between a finding and the index field by field.
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
        # BaseLocationComponentDTOV3.uuid -- see normalise_library_components.
        "library_uuid": component.get("uuid") or "",
    }


def _header_finding(findings: list, library: str):
    """The finding whose component metadata belongs in the work item HEADER.

    The header describes the work item's own library -- the root in dependency mode, the
    vulnerable library in per-CVE mode -- so the finding whose component.name equals that library
    is the correct source.

    Returns (finding, matched). `matched` tells render_inputs which source has priority: when a
    finding is about the entry's own library its project-specific component wins; when none is
    (the normal case for a root, which is usually not itself vulnerable) entry["component"], the
    root-keyed due-diligence row, wins instead, and the unmatched findings[0] is a last resort for
    fields the index leaves blank.

    In per-CVE mode the match always succeeds, since the entry's library is its findings'
    component.
    """
    for finding in findings:
        if (_walk(finding, "component", "name") or "") == (library or ""):
            return finding, True
    return (findings[0] if findings else None), False


def render_inputs(entry: dict) -> dict:
    """One `desired` entry ({"library", "kind", "findings"}) -> the flat inputs the HTML
    description builders consume.

    Never raises: every missing or malformed key yields "" or [], not None.

    A `kind == "license"` entry carries ProjectViolationDTOV3 objects rather than findings, and
    that DTO has no component, so its library metadata comes from entry["component"] -- the index
    normalise_library_components builds from the due-diligence rows and core.fetch_v3_desired
    attaches. `vulnerabilities` and `parents` stay empty for a license entry: there is no finding
    to read a CVE or a dependency hierarchy from.

    A vulnerability entry reads its own finding first, since BaseLocationComponentDTOV3 with
    libraryLocations is richer and project-specific, and falls back to entry["component"] only for
    a field the finding leaves blank.

    Which finding supplies the header is decided by _header_finding: under root grouping one entry
    holds findings for many libraries, and the finding whose component is the entry's own library
    wins.
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
        "library_uuid": "",
        "parents": [],
        "vulnerabilities": [],
        "paths": [],
    }
    if not isinstance(entry, dict):
        return result

    # Set before either branch returns, so a license entry (which returns early below) gets it
    # too. Guarded to a list of non-empty lists of strings; anything else yields [].
    raw_paths = entry.get("paths")
    if isinstance(raw_paths, list):
        result["paths"] = [p for p in raw_paths
                            if isinstance(p, list) and p
                            and all(isinstance(name, str) for name in p)]

    if entry.get("kind") != "vulnerability":
        component = entry.get("component")
        if isinstance(component, dict):
            for key in ("version", "description", "dependency_type", "dependency_file",
                        "library_path", "home_page", "library_uuid"):
                result[key] = component.get(key) or ""
            # mend_url is not copied: it is the Hyperlink relation's value (see library_url),
            # not a line in the description.
        return result

    findings = [f for f in (entry.get("findings") or []) if isinstance(f, dict)]
    if not findings:
        return result

    source, matched = _header_finding(findings, library)
    source = source if isinstance(source, dict) else {}
    from_finding = _component_fields(source)

    component_index = entry.get("component")
    from_index = component_index if isinstance(component_index, dict) else {}

    # Priority order. A finding about this library beats the project-wide index, since its
    # BaseLocationComponentDTOV3 is richer and project-specific; a finding about another library
    # loses to it, since the index row is keyed by the work item's own library.
    sources = (from_finding, from_index) if matched else (from_index, from_finding)
    for key in ("version", "description", "dependency_type", "dependency_file",
                "library_path", "home_page", "library_uuid"):
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

    ComponentReferencesDTO.url is the library page; homePage is the upstream project's own site,
    so homePage is only a fallback.

    Priority: the finding whose component is the work item's own library, then
    entry["component"]["mend_url"] (the index row keyed by that same library), then any finding
    carrying a URL at all.

    A license entry has no component, since its violations are ProjectViolationDTOV3, so it reaches
    the index fallback -- the same due-diligence index the description reads.

    Returns "" when no source has one, and the caller then writes no relation at all rather than an
    empty one.
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

    ProjectViolationDTOV3.name is prefixed with a bracketed tag (e.g. "[Legal] No GPL"), and
    everything up to and including the first "]" is stripped.
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
