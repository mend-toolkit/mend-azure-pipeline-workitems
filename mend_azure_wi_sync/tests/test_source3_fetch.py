from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(org_uuid="org-1", ws_org_token="tok", email="a@b.com",
                          ws_url="saas.mend.io", proxy={})


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
    """findings/security and violations are both GET-only in the spec; only
    /projects/summaries is POST. Guards against the POST fix leaking onto these calls."""
    methods = []

    def fake_pages(api, params=None, limit=1000, method="GET"):
        methods.append(method)
        return ([_finding()], True) if "findings/security" in api else ([_violation()], True)

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages):
        core.fetch_v3_desired("p-1", 7.0)
    assert methods == ["GET", "GET"]


def test_an_empty_project_is_ok_with_an_empty_desired():
    """Genuinely nothing to do is a real answer and must be distinguishable from a failure."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([], True)):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert desired == {}
    assert ok is True
