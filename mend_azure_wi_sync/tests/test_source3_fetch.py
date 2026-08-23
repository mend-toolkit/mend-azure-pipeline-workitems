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


def test_vulnerabilities_and_licenses_merge_into_one_desired_map():
    def fake_pages(api, params=None, limit=1000):
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
        return ([_finding()], True) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    assert len(desired) == 2


def test_a_failed_findings_read_makes_the_whole_project_not_ok():
    """Closure safety: a partial read must never look like a shrunken one."""
    def fake_pages(api, params=None, limit=1000):
        return ([], False) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_a_failed_violations_read_also_makes_it_not_ok():
    def fake_pages(api, params=None, limit=1000):
        return ([_finding()], True) if "findings/security" in api else ([], False)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        _, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_desired_reads_stay_get_not_post():
    """findings/security, violations and the licenses due-diligence read are all GET-only in
    the spec; only /projects/summaries is POST. Guards against the POST fix leaking onto
    these calls."""
    methods = []

    def fake_pages(api, params=None, limit=1000, method="GET"):
        methods.append(method)
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
    # findings, violations, due-diligence licenses, and the library list.
    assert methods == ["GET", "GET", "GET", "GET"]


def _license_row(lib="log4j-core", name="MIT", url="https://opensource.org/licenses/MIT",
                 reference="https://repo.maven.apache.org/log4j-core.pom"):
    return {"name": name, "component": {"name": lib},
            "license": {"textUrl": url, "liabilityReference": reference}}


def _fake_pages_with_licenses(license_rows, license_ok=True):
    def fake_pages(api, params=None, limit=1000, method="GET"):
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
                                         "mend_url": ""}}
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
