from unittest import mock

import pytest

from mend_azure_wi_sync import core


@pytest.fixture(autouse=True)
def _reset_library_paths_breaker_state():
    # The circuit breaker is run-scoped module state, same as library_paths_cache. Without an
    # autouse reset, a test that trips it (or leaves failures short of the threshold) would leak
    # into every test that runs after it in this file.
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False
    yield
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False


def _conf(dependency="true"):
    # dependency is explicit: fetch_v3_desired now reads it to choose the grouping, and a bare
    # MagicMock attribute is not "true", which would silently put every test in per-CVE mode.
    # dep_paths/dep_paths_concurrency are explicit "" too: a bare MagicMock attribute is truthy
    # and not a real number, which would make library_paths_pool_size() log a bogus warning on
    # every batch fetch in this file.
    return mock.MagicMock(org_uuid="org-1", ws_org_token="tok", email="a@b.com",
                          ws_url="saas.mend.io", proxy={}, dependency=dependency,
                          dep_paths="", dep_paths_concurrency="")


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


def _reset_library_paths_breaker():
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False


def test_breaker_trips_after_threshold_consecutive_failures():
    _reset_library_paths_cache()
    _reset_library_paths_breaker()
    with mock.patch.object(core, "call_ws_api_v2", return_value=({}, 2)) as api, \
         mock.patch.object(core, "logger") as logger:
        for i in range(core.LIBRARY_PATHS_BREAKER_THRESHOLD):
            assert core.fetch_v2_library_paths("proj-1", f"lib-{i}") == []
    assert api.call_count == core.LIBRARY_PATHS_BREAKER_THRESHOLD
    assert core.library_paths_breaker_tripped is True
    # Logged once, clearly enough an operator understands hierarchies are degraded this run.
    assert logger.error.call_count == 1


def test_breaker_stops_all_http_calls_once_tripped():
    _reset_library_paths_cache()
    _reset_library_paths_breaker()
    with mock.patch.object(core, "call_ws_api_v2", return_value=({}, 2)) as api:
        for i in range(core.LIBRARY_PATHS_BREAKER_THRESHOLD):
            core.fetch_v2_library_paths("proj-1", f"lib-{i}")
        assert core.library_paths_breaker_tripped is True
        api.reset_mock()
        # A brand-new (project, library) pair -- not in the cache -- must still make no call.
        result = core.fetch_v2_library_paths("proj-1", "never-seen-before")
    assert result == []
    api.assert_not_called()


def test_a_success_before_the_threshold_resets_the_failure_count():
    _reset_library_paths_cache()
    _reset_library_paths_breaker()
    responses = [({}, 2), ({}, 2), (_PATHS_PAYLOAD, 0)]
    with mock.patch.object(core, "call_ws_api_v2", side_effect=responses):
        core.fetch_v2_library_paths("proj-1", "lib-1")
        core.fetch_v2_library_paths("proj-1", "lib-2")
        core.fetch_v2_library_paths("proj-1", "lib-3")
    assert core.library_paths_consecutive_failures == 0
    assert core.library_paths_breaker_tripped is False
    # Confirm it takes a fresh full run of failures to trip after the reset, not just one more.
    _reset_library_paths_cache()
    with mock.patch.object(core, "call_ws_api_v2", return_value=({}, 2)) as api:
        for _ in range(core.LIBRARY_PATHS_BREAKER_THRESHOLD - 1):
            core.fetch_v2_library_paths("proj-1", f"lib-x{_}")
    assert core.library_paths_breaker_tripped is False
    assert api.call_count == core.LIBRARY_PATHS_BREAKER_THRESHOLD - 1


def test_the_ok_interlock_stays_true_while_the_breaker_is_tripped():
    """The breaker must never touch fetch_v3_desired's `ok` closure interlock -- decorative
    dependency paths can never gate closure, tripped or not."""
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_transitive_finding(cve=f"CVE-{i}", uuid=f"lib-uuid-{i}")
                    for i in range(core.LIBRARY_PATHS_BREAKER_THRESHOLD + 1)], True
        return [_violation()], True

    _reset_library_paths_cache()
    _reset_library_paths_breaker()
    with mock.patch.object(core, "conf", _conf(dependency="false")), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"error": "nope"}, 2)):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    assert core.library_paths_breaker_tripped is True


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
    with mock.patch.object(core, "_fetch_paths_batch") as batch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    batch.assert_not_called()
    assert "paths" not in desired[("license", "log4j-core")]


def test_attach_library_paths_is_case_insensitive_on_dependency_type():
    _reset_library_paths_cache()
    desired = {("license", "log4j-core"): _entry(kind="license", dependency_type="TRANSITIVE")}
    with mock.patch.object(core, "_fetch_paths_batch",
                           return_value={"lib-1": (_PATHS_PAYLOAD, 0)}) as batch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    batch.assert_called_once_with("proj-1", ["lib-1"])
    assert desired[("license", "log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_skips_uuid_less_entries():
    desired = {("license", "log4j-core"): _entry(kind="license", library_uuid="")}
    with mock.patch.object(core, "_fetch_paths_batch") as batch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    batch.assert_not_called()
    assert "paths" not in desired[("license", "log4j-core")]


def test_attach_library_paths_skips_vulnerability_entries_in_root_grouping_mode():
    desired = {("vulnerability", "log4j-core"): _entry(kind="vulnerability")}
    with mock.patch.object(core, "_fetch_paths_batch") as batch:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    batch.assert_not_called()
    assert "paths" not in desired[("vulnerability", "log4j-core")]


def test_attach_library_paths_fetches_vulnerability_entries_in_per_cve_mode():
    _reset_library_paths_cache()
    desired = {("vulnerability", "CVE-1|log4j-core"): _entry(kind="vulnerability")}
    with mock.patch.object(core, "_fetch_paths_batch",
                           return_value={"lib-1": (_PATHS_PAYLOAD, 0)}) as batch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    batch.assert_called_once_with("proj-1", ["lib-1"])
    assert desired[("vulnerability", "CVE-1|log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_fetches_a_transitive_license_entry():
    _reset_library_paths_cache()
    desired = {("license", "log4j-core"): _entry(kind="license")}
    with mock.patch.object(core, "_fetch_paths_batch",
                           return_value={"lib-1": (_PATHS_PAYLOAD, 0)}) as batch:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    batch.assert_called_once_with("proj-1", ["lib-1"])
    assert desired[("license", "log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_batches_several_entries_sharing_one_uuid_into_one_call():
    """forever's 51 findings on one library must still cost ONE /paths call, not 51 --
    now proven at the attach_library_paths -> _fetch_paths_batch boundary rather than via
    fetch_v2_library_paths' own memoisation, since the batch path no longer calls through it."""
    _reset_library_paths_cache()
    desired = {
        ("vulnerability", "CVE-1|log4j-core"): _entry(kind="vulnerability", library_uuid="lib-1"),
        ("vulnerability", "CVE-2|log4j-core"): _entry(kind="vulnerability", library_uuid="lib-1"),
    }
    with mock.patch.object(core, "_fetch_paths_batch",
                           return_value={"lib-1": (_PATHS_PAYLOAD, 0)}) as batch:
        core.attach_library_paths("proj-1", desired, per_cve=True)
    batch.assert_called_once_with("proj-1", ["lib-1"])
    assert desired[("vulnerability", "CVE-1|log4j-core")]["paths"] == _PATHS_CHAINS
    assert desired[("vulnerability", "CVE-2|log4j-core")]["paths"] == _PATHS_CHAINS


def test_attach_library_paths_does_not_refetch_uuids_already_in_the_cache():
    _reset_library_paths_cache()
    core.library_paths_cache[("proj-1", "lib-1")] = _PATHS_CHAINS
    desired = {("license", "log4j-core"): _entry(kind="license")}
    with mock.patch.object(core, "_fetch_paths_batch") as batch:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    batch.assert_not_called()
    assert desired[("license", "log4j-core")]["paths"] == _PATHS_CHAINS


def _transitive_finding(cve="CVE-1", lib="log4j-core", uuid="lib-uuid-1"):
    """A per-CVE finding whose component IS uuid-bearing and TRANSITIVE, so
    attach_library_paths actually calls through to fetch_v2_library_paths rather than skipping
    the entry for lack of a library_uuid."""
    return {"name": cve, "findingInfo": {"status": "ACTIVE"},
           "component": {"name": lib, "uuid": uuid, "dependencyType": "TRANSITIVE"},
           "vulnerability": {"name": cve, "score": 9.8}}


def test_an_empty_attach_pass_leaves_fetch_v3_desired_ok_true():
    """A project with nothing uuid-bearing/transitive: attach_library_paths runs but never calls
    through. Kept alongside the end-to-end failure test below because it pins down the OTHER
    half of the interlock claim -- that simply running attach_library_paths costs nothing when
    there is nothing to fetch."""
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_finding()], True
        return [_violation()], True

    _reset_library_paths_cache()
    with mock.patch.object(core, "conf", _conf(dependency="false")), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages), \
         mock.patch.object(core, "mend_v2_token") as token_mock, \
         mock.patch.object(core, "_get_v2") as get_mock:
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    assert desired
    # No library_uuid on the stub finding/violation, so nothing was actually fetched.
    token_mock.assert_not_called()
    get_mock.assert_not_called()


def test_a_failed_paths_call_leaves_fetch_v3_desired_ok_true():
    """The closure interlock: a decorative /paths failure must never gate `ok`. This is the
    most important test in this task -- it must exercise a REAL batch fetch that actually fails,
    not an entry attach_library_paths skips before ever reaching it."""
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if _is_root_path(api):
            return [], True
        if "findings/security" in api:
            return [_transitive_finding()], True
        return [_violation()], True

    _reset_library_paths_cache()
    with mock.patch.object(core, "conf", _conf(dependency="false")), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           return_value=({"error": "nope"}, 2)) as get_mock:
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    # The call genuinely happened and genuinely failed -- proving the interlock actually held
    # under a real failure, not merely under an entry that was skipped beforehand.
    get_mock.assert_called_once()
    called_url = get_mock.call_args[0][0]
    assert called_url.endswith("projects/p-1/libraries/lib-uuid-1/paths")
    entry = desired[("vulnerability", "CVE-1|log4j-core")]
    assert entry["paths"] == []
