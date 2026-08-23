"""The root library index: Mend's remediation verdict per root library.

GET /projects/{uuid}/dependencies/findings/security/groupBy/rootLibrary returns
RootLibrarySecurityFindingDTOV3. It supplies REMEDIATION ONLY -- it never decides which work items
exist, because its counts include suppressed findings (body-parser reports total 5 while 2 are
IGNORED) and it is not MEND_SEVERITY-aware. The item set comes from surviving findings; see
test_root_grouping.py.
"""

from mend_azure_wi_sync import source3


def _root_row(name="express-4.16.4.tgz", version="4.16.4", recommended="4.22.2",
              major="5.2.1", failed=False, total=13):
    """One RootLibrarySecurityFindingDTOV3, shaped like the live response."""
    row = {
        "rootLibraryName": name,
        "rootLibraryUuid": "16027327-7a30-4db5-bb7d-a09681d5a32d",
        "rootLibraryVersion": version,
        "recommendedFix": recommended,
        "suggestedFixFailed": failed,
        "severity": "HIGH",
        "total": total,
        "criticalNum": 0, "highNum": 5, "mediumNum": 5, "lowNum": 3,
        "dependencyFile": "/home/vsts/work/1/s/package.json",
    }
    if major:
        row["fixForMajorVersion"] = major
    return row


def test_the_index_is_keyed_by_root_name_and_carries_the_remediation_fields():
    assert source3.normalise_root_libraries([_root_row()]) == {"express-4.16.4.tgz": {
        "version": "4.16.4",
        "recommended_fix": "4.22.2",
        "major_fix": "5.2.1",
        "fix_failed": False,
        "severity": "HIGH",
        "total": 13,
    }}


def test_a_root_with_no_major_fix_gets_an_empty_string_not_none():
    """swig, underscore, csurf and express-session all lack fixForMajorVersion live."""
    index = source3.normalise_root_libraries([_root_row(name="swig-1.4.2.tgz", major=None)])
    assert index["swig-1.4.2.tgz"]["major_fix"] == ""


def test_suggested_fix_failed_is_carried_as_a_bool():
    index = source3.normalise_root_libraries([_root_row(failed=True)])
    assert index["express-4.16.4.tgz"]["fix_failed"] is True


def test_a_non_bool_fix_failed_is_coerced_rather_than_leaking():
    index = source3.normalise_root_libraries([_root_row(failed="yes")])
    assert index["express-4.16.4.tgz"]["fix_failed"] is True
    index = source3.normalise_root_libraries([_root_row(failed=None)])
    assert index["express-4.16.4.tgz"]["fix_failed"] is False


def test_a_row_with_no_root_name_is_skipped():
    rows = [{"recommendedFix": "1.0.0"}, _root_row()]
    assert list(source3.normalise_root_libraries(rows)) == ["express-4.16.4.tgz"]


def test_a_missing_total_becomes_zero_and_a_garbage_total_does_not_raise():
    row = _root_row(total=None)
    row.pop("total")
    assert source3.normalise_root_libraries([row])["express-4.16.4.tgz"]["total"] == 0
    row["total"] = "lots"
    assert source3.normalise_root_libraries([row])["express-4.16.4.tgz"]["total"] == 0


def test_the_last_row_wins_for_a_repeated_root():
    """One row per root per project is expected; if the server repeats one, take the later row
    rather than merging two remediation verdicts into a hybrid that Mend never issued."""
    rows = [_root_row(recommended="4.0.0"), _root_row(recommended="4.22.2")]
    assert source3.normalise_root_libraries(rows)["express-4.16.4.tgz"]["recommended_fix"] == "4.22.2"


def test_garbage_input_returns_an_empty_index():
    assert source3.normalise_root_libraries(None) == {}
    assert source3.normalise_root_libraries(["nope", 42, None]) == {}
    assert source3.normalise_root_libraries([]) == {}


# --------------------------------------------------------------------------- the fetch and join

from unittest import mock

from mend_azure_wi_sync import core


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false", reponame="",
                  routing="false", description="ReproSteps", priority="false", azure_area="",
                  azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _security_finding(lib="qs-6.5.2.tgz", root="express-4.16.4.tgz"):
    return {
        "findingInfo": {"status": "ACTIVE"},
        "component": {"name": lib, "version": "6.5.2"},
        "vulnerability": {"name": "CVE-2022-24999", "score": 7.5, "severity": "HIGH"},
        "dependencyContexts": [{"isTransitive": True, "directRoots": [
            {"rootLibraryName": root, "rootLibraryVersion": "4.16.4"}]}],
    }


def _pages(root_rows, roots_ok=True, findings=None):
    def pages(path, **kwargs):
        if path.endswith("groupBy/rootLibrary"):
            return root_rows, roots_ok
        if path.endswith("findings/security"):
            return (findings if findings is not None else [_security_finding()]), True
        return [], True
    return pages


def test_the_root_index_is_fetched_and_keyed_by_name():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([_root_row()], True)):
        index, ok = core.fetch_v3_root_libraries("p-1")
    assert ok is True
    assert index["express-4.16.4.tgz"]["recommended_fix"] == "4.22.2"


def test_the_call_is_a_get_on_the_group_by_root_library_path():
    seen = {}

    def pages(path, params=None, limit=1000, method="GET"):
        seen["path"], seen["method"] = path, method
        return [], True

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", pages):
        core.fetch_v3_root_libraries("p-1")
    assert seen["path"] == "projects/p-1/dependencies/findings/security/groupBy/rootLibrary"
    assert seen["method"] == "GET"


def test_a_failed_root_read_reports_not_ok():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_pages", return_value=([], False)):
        index, ok = core.fetch_v3_root_libraries("p-1")
    assert (index, ok) == ({}, False)


def test_desired_entries_carry_their_root_index_row():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _pages([_root_row()])):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    entry = desired[("vulnerability", "express-4.16.4.tgz")]
    assert entry["root"]["recommended_fix"] == "4.22.2"
    assert entry["root"]["major_fix"] == "5.2.1"


def test_a_root_with_no_index_row_gets_an_empty_dict_not_a_missing_key():
    """The renderer must never KeyError, and an absent row must render no remediation lines."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _pages([])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    assert desired[("vulnerability", "express-4.16.4.tgz")]["root"] == {}


def test_a_failed_root_read_clears_the_closure_interlock():
    """Same rule as every other read: a partial read must never be mistaken for a shrunken
    desired, or reconciliation closes live work items."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _pages([], roots_ok=False)):
        _, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_a_license_entry_does_not_gain_a_root_key():
    """Root grouping is a vulnerability concept; a license item is about the library itself."""
    def pages(path, **kwargs):
        if path.endswith("groupBy/rootLibrary"):
            return [_root_row()], True
        if path.endswith("/violations"):
            return [{"findingType": "LEGAL", "originName": "log4j-core",
                     "name": "[Legal] No GPL"}], True
        return [], True

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", pages):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    assert "root" not in desired[("license", "log4j-core")]
