from unittest import mock

from mend_azure_wi_sync import core


def _conf(dependency="true"):
    # dependency is explicit: fetch_v3_desired now reads it to choose the grouping, and a bare
    # MagicMock attribute is not "true", which would silently put every test in per-CVE mode.
    return mock.MagicMock(org_uuid="org-1", ws_org_token="tok", email="a@b.com",
                          ws_url="saas.mend.io", proxy={}, dependency=dependency)


def test_projects_are_fetched_and_normalised():
    rows = [{"uuid": "p-1", "name": "api", "applicationUuid": "a-1",
             "applicationName": "ProductX", "lastScanned": "2026-08-20", "tags": []}]
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=(rows, True)):
        projects, ok = core.fetch_v3_projects()
    assert ok is True
    assert projects[0]["uuid"] == "p-1"


def test_projects_are_fetched_with_method_post():
    """/projects/summaries is POST-only in the 3.0 spec; a GET-only transport 404s/405s."""
    captured = {}

    def fake_pages(api, params=None, limit=1000, method="GET"):
        captured["method"] = method
        return [], True

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        core.fetch_v3_projects()
    assert captured["method"] == "POST"


def test_a_failed_project_fetch_reports_not_ok():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([], False)):
        projects, ok = core.fetch_v3_projects()
    assert ok is False


def _finding(cve="CVE-1", lib="log4j-core"):
    return {"name": cve, "findingInfo": {"status": "ACTIVE"},
            "component": {"name": lib}, "vulnerability": {"name": cve, "score": 9.8}}


def _violation(lib="log4j-core"):
    return {"findingType": "LEGAL", "originName": lib, "name": "GPL-3.0"}


# The root-library index lives at .../dependencies/findings/security/groupBy/rootLibrary, which
# CONTAINS "findings/security". Every stub below therefore has to match it FIRST, or the root call
# is served the findings payload -- and a stub asserting "the findings read failed" was silently
# failing the root read too.
def _is_root_path(api):
    return api.endswith("groupBy/rootLibrary")


def test_vulnerabilities_and_licenses_merge_into_one_desired_map():
    def fake_pages(api, params=None, limit=1000):
        if _is_root_path(api):
            return [], True
        return ([_finding()], True) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    assert ("vulnerability", "log4j-core") in desired
    assert ("license", "log4j-core") in desired


def test_a_library_with_both_kinds_produces_two_separate_entries():
    """They are two work items with different titles; keying on library alone would lose one."""
    def fake_pages(api, params=None, limit=1000):
        if _is_root_path(api):
            return [], True
        return ([_finding()], True) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    assert len(desired) == 2


def test_a_failed_findings_read_makes_the_whole_project_not_ok():
    """Closure safety: a partial read must never look like a shrunken one."""
    def fake_pages(api, params=None, limit=1000):
        if _is_root_path(api):
            return [], True
        return ([], False) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_a_failed_violations_read_also_makes_it_not_ok():
    def fake_pages(api, params=None, limit=1000):
        if _is_root_path(api):
            return [], True
        return ([_finding()], True) if "findings/security" in api else ([], False)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        _, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_desired_reads_stay_get_not_post():
    """findings/security, violations, the licenses due-diligence read, the library list, and the
    root-library remediation index are all GET-only in the spec; only /projects/summaries is
    POST. Guards against the POST fix leaking onto these calls."""
    methods = []

    def fake_pages(api, params=None, limit=1000, method="GET"):
        methods.append(method)
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_finding()], True
        if "libraries/licenses" in api:
            return [], True
        if api.endswith("dependencies/libraries"):
            return [], True
        return [_violation()], True

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        core.fetch_v3_desired("p-1", 7.0)
    # findings, violations, due-diligence licenses, the library list, and the root-library
    # remediation index (Task 5) -- one more GET, folded into the same interlock as the rest.
    assert methods == ["GET", "GET", "GET", "GET", "GET"]


def _license_row(lib="log4j-core", name="MIT", url="https://opensource.org/licenses/MIT",
                 reference="https://repo.maven.apache.org/log4j-core.pom"):
    return {"name": name, "component": {"name": lib},
            "license": {"textUrl": url, "liabilityReference": reference}}


def _fake_pages_with_licenses(license_rows, license_ok=True):
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_finding()], True
        if "libraries/licenses" in api:
            return license_rows, license_ok
        return [_violation()], True
    return fake_pages


def test_desired_entries_carry_the_license_index():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_with_licenses([_license_row()])):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    assert desired[("vulnerability", "log4j-core")]["licenses"] == [
        {"name": "MIT", "url": "https://opensource.org/licenses/MIT",
         "reference_file": "https://repo.maven.apache.org/log4j-core.pom"}]
    assert desired[("license", "log4j-core")]["licenses"] == [
        {"name": "MIT", "url": "https://opensource.org/licenses/MIT",
         "reference_file": "https://repo.maven.apache.org/log4j-core.pom"}]


def test_a_library_with_no_licenses_gets_an_empty_list_not_a_missing_key():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_with_licenses([])):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    assert desired[("vulnerability", "log4j-core")]["licenses"] == []
    assert "licenses" in desired[("vulnerability", "log4j-core")]


def test_a_failed_license_read_ands_ok_to_false():
    """A failed license read must not make a library look license-free -- it must fail the
    whole closure interlock, exactly like a failed findings or violations read."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages",
                            _fake_pages_with_licenses([], license_ok=False)):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_a_successful_license_read_leaves_ok_true():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_with_licenses([_license_row()])):
        _, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True


def test_fetch_v3_licenses_normalises_and_reports_ok():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([_license_row()], True)):
        index, components, ok = core.fetch_v3_licenses("p-1")
    assert ok is True
    assert components == {"log4j-core": {"version": "", "description": "",
                                         "dependency_type": "", "dependency_file": "",
                                         "library_path": "", "home_page": "",
                                         "mend_url": "", "library_uuid": ""}}
    assert index == {"log4j-core": [
        {"name": "MIT", "url": "https://opensource.org/licenses/MIT",
         "reference_file": "https://repo.maven.apache.org/log4j-core.pom"}]}


def test_fetch_v3_licenses_reports_failure():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([], False)):
        index, components, ok = core.fetch_v3_licenses("p-1")
    assert ok is False
    assert (index, components) == ({}, {})


def test_an_empty_project_is_ok_with_an_empty_desired():
    """Genuinely nothing to do is a real answer and must be distinguishable from a failure."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([], True)):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert desired == {}
    assert ok is True


# --- fetch_v2_library_paths / attach_library_paths --------------------------------------------

_PATHS_PAYLOAD = {"retVal": [
    {"libraryPath": [{"uuid": "u1", "name": "app", "order": 0},
                     {"uuid": "u2", "name": "express", "order": 1},
                     {"uuid": "u3", "name": "body-parser", "order": 2}]},
    {"libraryPath": [{"uuid": "u1", "name": "app", "order": 0},
                     {"uuid": "u4", "name": "webpack", "order": 1},
                     {"uuid": "u3", "name": "body-parser", "order": 2}]},
]}
_PATHS_CHAINS = [["app", "express", "body-parser"], ["app", "webpack", "body-parser"]]


def _reset_library_paths_cache():
    core.library_paths_cache = {}


def test_fetch_v2_library_paths_normalises_a_successful_call():
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_PATHS_PAYLOAD, 0)) as api:
        paths = core.fetch_v2_library_paths("proj-1", "lib-1")
    api.assert_called_once_with("projects/proj-1/libraries/lib-1/paths")
    assert paths == _PATHS_CHAINS


def test_fetch_v2_library_paths_failure_logs_and_returns_empty_list():
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2", return_value=({"error": "nope"}, 2)):
        paths = core.fetch_v2_library_paths("proj-1", "lib-1")
    assert paths == []


def test_fetch_v2_library_paths_missing_ids_never_call():
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2") as api:
        assert core.fetch_v2_library_paths("", "lib-1") == []
        assert core.fetch_v2_library_paths("proj-1", "") == []
    api.assert_not_called()


def test_fetch_v2_library_paths_is_memoised_across_calls():
    """forever's 51 findings on one library must cost ONE HTTP call, not 51."""
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_PATHS_PAYLOAD, 0)) as api:
        first = core.fetch_v2_library_paths("proj-1", "lib-1")
        second = core.fetch_v2_library_paths("proj-1", "lib-1")
    assert first == second == _PATHS_CHAINS
    api.assert_called_once()


def test_fetch_v2_library_paths_caches_a_failure_too():
    """A PAT lacking permission for this endpoint must not be retried on every finding."""
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2", return_value=({}, 2)) as api:
        first = core.fetch_v2_library_paths("proj-1", "lib-1")
        second = core.fetch_v2_library_paths("proj-1", "lib-1")
    assert first == second == []
    api.assert_called_once()


def _entry(kind="vulnerability", dependency_type="Transitive", library_uuid="lib-1",
          library="log4j-core"):
    """A minimal `desired` entry for attach_library_paths tests, matching what render_inputs
    actually reads for each kind: a license (or any non-vulnerability) entry reads
    entry["component"], a vulnerability entry reads entry["findings"][*]["component"] for the
    finding whose component.name matches the entry's own library (see source3._header_finding)."""
    if kind == "vulnerability":
        return {"kind": kind, "library": library,
               "findings": [{"component": {"name": library, "uuid": library_uuid,
                                           "dependencyType": dependency_type}}],
               "component": {}}
    return {"kind": kind, "library": library, "findings": [],
           "component": {"dependency_type": dependency_type, "library_uuid": library_uuid}}


def test_attach_library_paths_skips_direct_dependencies():
    desired = {("license", "log4j-core"): _entry(kind="license", dependency_type="Direct")}
    with mock.patch.object(core, "fetch_v2_library_paths") as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    fetch.assert_not_called()
    assert "paths" not in desired[("license", "log4j-core")]


def test_attach_library_paths_is_case_insensitive_on_dependency_type():
    desired = {("license", "log4j-core"): _entry(kind="license", dependency_type="TRANSITIVE")}
    with mock.patch.object(core, "fetch_v2_library_paths", return_value=_PATHS_CHAINS) as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    fetch.assert_called_once_with("proj-1", "lib-1")
    assert desired[("license", "log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_skips_uuid_less_entries():
    desired = {("license", "log4j-core"): _entry(kind="license", library_uuid="")}
    with mock.patch.object(core, "fetch_v2_library_paths") as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    fetch.assert_not_called()
    assert "paths" not in desired[("license", "log4j-core")]


def test_attach_library_paths_skips_vulnerability_entries_in_root_grouping_mode():
    desired = {("vulnerability", "log4j-core"): _entry(kind="vulnerability")}
    with mock.patch.object(core, "fetch_v2_library_paths") as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    fetch.assert_not_called()
    assert "paths" not in desired[("vulnerability", "log4j-core")]


def test_attach_library_paths_fetches_vulnerability_entries_in_per_cve_mode():
    desired = {("vulnerability", "CVE-1|log4j-core"): _entry(kind="vulnerability")}
    with mock.patch.object(core, "fetch_v2_library_paths", return_value=_PATHS_CHAINS) as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    fetch.assert_called_once_with("proj-1", "lib-1")
    assert desired[("vulnerability", "CVE-1|log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_fetches_a_transitive_license_entry():
    desired = {("license", "log4j-core"): _entry(kind="license")}
    with mock.patch.object(core, "fetch_v2_library_paths", return_value=_PATHS_CHAINS) as fetch:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    fetch.assert_called_once_with("proj-1", "lib-1")
    assert desired[("license", "log4j-core")]["paths"] == _PATHS_CHAINS


def test_a_failed_paths_call_leaves_fetch_v3_desired_ok_true():
    """The closure interlock: a decorative /paths failure must never gate `ok`. This is the
    most important test in this task."""
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_finding()], True
        return [_violation()], True

    _reset_library_paths_cache()
    with mock.patch.object(core, "conf", _conf(dependency="false")), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages), \
         mock.patch.object(core, "call_ws_api_v2", return_value=({"error": "nope"}, 2)):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    # No library_uuid on the stub finding/violation, so nothing was actually fetched -- the point
    # of this test is that even if it HAD been, a failure could not have touched `ok`.
    assert desired
