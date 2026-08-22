"""create_wi_v3 -- the 3.0 creation path.

The riskiest thing in this file is not the HTML: it is the TITLES. classify_title decodes a work
item's title back into the (kind, library) key that closure acts on, so a title this path renders
that classify_title cannot decode is a work item that either never closes or closes something
else. Every dependency-mode title generated here is asserted to round-trip.
"""

from unittest import mock

from mend_azure_wi_sync import core, source3


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", epss="false", reachability="false",
                  reponame="", routing="false", description="Description", priority="false",
                  azure_area="", azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _finding(cve="CVE-2020-8203", score=7.4, severity="high", lib="lodash"):
    return {
        "component": {
            "name": lib,
            "description": "Lodash modular utilities.",
            "version": "4.17.15",
            "dependencyType": "Direct",
            "dependencyFile": "package.json",
            "localPath": "/app/node_modules/lodash",
            "references": {"homePage": "https://lodash.com/",
                           "url": "https://mend.example/library/lodash"},
        },
        "dependencyContexts": [{"isDirect": True, "directRoots": [
            {"rootLibraryName": "app", "rootLibraryVersion": "1.0.0"}]}],
        "vulnerability": {
            "name": cve,
            "description": "Prototype pollution.",
            "score": score,
            "severity": severity,
            "publishDate": "2020-07-15",
            "references": [{"url": "https://example.com/patch", "patch": True},
                           {"url": "https://nvd.nist.gov/vuln/" + cve, "advisory": True}],
        },
        "topFix": {"type": "upgrade", "url": "https://example.com/fix",
                   "fixResolution": "Upgrade to 4.17.19", "date": "2020-08-01"},
        "threatAssessment": {"epssPercentage": 12.5, "exploitCodeMaturity": "POC"},
        "reachability": "REACHABLE",
        "findingInfo": {"status": "ACTIVE"},
    }


def _vuln_entry(*findings, licenses=None):
    return {"library": "lodash", "kind": "vulnerability", "findings": list(findings),
            "licenses": licenses or []}


def _license_entry(lib="lodash"):
    return {"library": lib, "kind": "license",
            "findings": [{"findingType": "LEGAL", "originName": lib,
                          "name": "[Legal] No copyleft", "uuid": "v-1"}],
            "licenses": [{"name": "GPL-3.0", "url": "https://spdx.org/gpl",
                          "reference_file": "pom.xml"}]}


_PROJECT = {"uuid": "p-1", "name": "Proj", "application_name": "Prod"}


def _run(desired, conf=None, azure=None, cstm_flds=None):
    """Drive create_wi_v3 with every Azure call doubled. Returns (result, mock_call_azure_api)."""
    conf = conf or _conf()
    azure = azure or mock.MagicMock(return_value=({"id": 42, "fields": {"System.State": "New"}}, 0))
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        result = core.create_wi_v3(_PROJECT, desired, cstm_flds or [], "Task")
    return result, azure


def _posted(azure):
    """The JSON document bodies of every POST that created a work item."""
    return [c.kwargs["data"] for c in azure.call_args_list
            if c.kwargs.get("api_type") == "POST" and "wit/workitems/$" in c.kwargs.get("api", "")]


def _field(document, path):
    for op in document:
        if op.get("path") == path:
            return op.get("value")
    return None


# --- titles: the contract closure depends on -------------------------------------------------

def test_dependency_mode_titles_round_trip_through_classify_title():
    """EVERY dependency-mode title must decode back to the key it was built for. A title that
    does not round-trip strands its work item open forever (closure never finds it) or, worse,
    decodes to another library's key and closes that one instead."""
    desired = {
        ("vulnerability", "lodash"): _vuln_entry(_finding(), _finding(cve="CVE-2021-23337",
                                                                      score=9.1)),
        ("license", "lodash"): _license_entry(),
        ("vulnerability", "log4j-core"): {
            "library": "log4j-core", "kind": "vulnerability",
            "findings": [_finding(cve="CVE-2021-44228", score=10.0, lib="log4j-core")],
            "licenses": []},
    }
    conf = _conf()
    with mock.patch.object(core, "conf", conf):
        for (kind, library), entry in desired.items():
            for item in core.render_entry_v3(kind, library, entry, False):
                assert core.classify_title(item["title"]) == (kind, library), item["title"]


def test_dependency_mode_vulnerability_title_is_byte_identical_to_the_shipped_format():
    conf = _conf()
    entry = _vuln_entry(_finding(), _finding(cve="CVE-2021-23337", score=9.1))
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "lodash", entry, False)
    assert len(items) == 1
    assert items[0]["title"] == "lodash: 2 vulnerabilities (highest severity is 9.1)"


def test_unscored_library_still_produces_a_title_that_round_trips():
    """max score is "" when Mend has scored nothing -- identity.matches_library tolerates the
    empty score group precisely so this title still resolves to its library."""
    conf = _conf()
    finding = _finding(score=None)
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "lodash", _vuln_entry(finding), False)
    assert items[0]["title"] == "lodash: 1 vulnerabilities (highest severity is )"
    assert core.classify_title(items[0]["title"]) == ("vulnerability", "lodash")


def test_license_title_is_the_shared_identity_format():
    conf = _conf()
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("license", "lodash", _license_entry(), False)
    assert items[0]["title"] == "License Policy Violation detected in lodash"
    assert items[0]["exact"] is True


def test_per_cve_mode_titles_match_the_shipped_format():
    conf = _conf(dependency="false")
    entry = _vuln_entry(_finding(), _finding(cve="CVE-2021-23337", score=9.1, severity="critical"))
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "lodash", entry, False)
    assert [i["title"] for i in items] == [
        "CVE-2021-23337 (Critical) detected in lodash",
        "CVE-2020-8203 (High) detected in lodash",
    ]


def test_per_cve_titles_are_not_classifiable_which_is_the_1_4_behaviour_too():
    """DOCUMENTED LIMITATION, not a regression: classify_title only decodes the two
    dependency-mode formats, so per-CVE mode (MEND_DEPENDENCY=false) has never supported
    closure -- on 1.4 either. Asserted so a future change to classify_title has to come past
    this test deliberately."""
    conf = _conf(dependency="false")
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "lodash", _vuln_entry(_finding()), False)
    assert core.classify_title(items[0]["title"]) is None


# --- rendering -------------------------------------------------------------------------------

def test_dependency_mode_renders_one_table_row_per_cve():
    desired = {("vulnerability", "lodash"): _vuln_entry(
        _finding(), _finding(cve="CVE-2021-23337", score=9.1))}
    (created, updated, failed), azure = _run(desired)
    assert (created, updated, failed) == (1, 0, 0)
    desc = _field(_posted(azure)[0], "/fields/System.Description")
    assert desc.count("<tr>") == 3            # header + one row per CVE
    assert "CVE-2020-8203" in desc and "CVE-2021-23337" in desc


def test_epss_and_exploit_render_even_though_mend_epss_is_false():
    """The MEND_EPSS gate is gone on 3.0: both values arrive inline with the finding, so there
    is nothing to spare an org by hiding them."""
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    (_, _, _), azure = _run(desired, conf=_conf(epss="false"))
    desc = _field(_posted(azure)[0], "/fields/System.Description")
    assert "<b>EPSS</b>" in desc and "<b>Exploit</b>" in desc          # table headers
    assert "<b>EPSS:</b> 12.5%" in desc
    assert "<b>Exploit Code Maturity:</b>" in desc


def test_reachability_stays_gated_on_mend_reachability():
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    (_, _, _), off = _run(desired, conf=_conf(reachability="false"))
    assert "Reachability" not in _field(_posted(off)[0], "/fields/System.Description")
    (_, _, _), on = _run(desired, conf=_conf(reachability="true"))
    desc = _field(_posted(on)[0], "/fields/System.Description")
    assert "<b>Reachability</b>" in desc and "<b>Reachability:</b>" in desc


def test_per_cve_mode_creates_one_work_item_per_cve():
    desired = {("vulnerability", "lodash"): _vuln_entry(
        _finding(), _finding(cve="CVE-2021-23337", score=9.1))}
    (created, updated, failed), azure = _run(desired, conf=_conf(dependency="false"))
    assert (created, updated, failed) == (2, 0, 0)
    titles = [_field(d, "/fields/System.Title") for d in _posted(azure)]
    assert sorted(titles) == ["CVE-2020-8203 (High) detected in lodash",
                              "CVE-2021-23337 (High) detected in lodash"]


def test_license_entry_renders_the_license_work_item():
    desired = {("license", "lodash"): _license_entry()}
    (created, updated, failed), azure = _run(desired)
    assert (created, updated, failed) == (1, 0, 0)
    document = _posted(azure)[0]
    assert _field(document, "/fields/System.Title") == "License Policy Violation detected in lodash"
    desc = _field(document, "/fields/System.Description")
    assert "License Details" in desc and "GPL-3.0" in desc
    assert "<b>License Policy Violation - </b>No copyleft" in desc
    assert _field(document, "/fields/System.Tags") == "Prod/Proj,license policy violation"


def test_vulnerability_work_item_carries_the_vulnerability_tag():
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    _, azure = _run(desired)
    assert _field(_posted(azure)[0], "/fields/System.Tags") == "Prod/Proj,security vulnerability"


def test_priority_is_derived_from_the_max_score_when_enabled():
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding(score=9.8))}
    _, azure = _run(desired, conf=_conf(priority="true"))
    assert _field(_posted(azure)[0], "/fields/Microsoft.VSTS.Common.Priority") == 1
    _, azure = _run(desired, conf=_conf(priority="false"))
    assert _field(_posted(azure)[0], "/fields/Microsoft.VSTS.Common.Priority") == 2


# --- the hyperlink relation ------------------------------------------------------------------

def test_hyperlink_points_at_the_library_page_with_no_comment_attribute():
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    _, azure = _run(desired)
    relations = [op for op in _posted(azure)[0] if op["path"] == "/relations/-"]
    assert relations == [{"op": "add", "path": "/relations/-",
                          "value": {"rel": "Hyperlink",
                                    "url": "https://mend.example/library/lodash"}}]


def test_hyperlink_falls_back_to_the_home_page():
    finding = _finding()
    finding["component"]["references"] = {"homePage": "https://lodash.com/"}
    desired = {("vulnerability", "lodash"): _vuln_entry(finding)}
    _, azure = _run(desired)
    relations = [op for op in _posted(azure)[0] if op["path"] == "/relations/-"]
    assert relations[0]["value"]["url"] == "https://lodash.com/"


def test_no_relation_is_written_when_the_library_has_no_url():
    finding = _finding()
    finding["component"].pop("references")
    desired = {("vulnerability", "lodash"): _vuln_entry(finding)}
    _, azure = _run(desired)
    assert [op for op in _posted(azure)[0] if op["path"] == "/relations/-"] == []


# --- matching an item that already exists ----------------------------------------------------

def _azure_double(existing_type="Task"):
    def _call(**kwargs):
        if kwargs.get("api_type") == "GET":
            return {"fields": {"System.WorkItemType": existing_type}}, 0
        return {"id": 77, "fields": {"System.State": "Active"}}, 0
    return mock.MagicMock(side_effect=_call)


def test_existing_item_is_patched_not_duplicated_even_though_the_count_moved():
    """The stored title says 5 vulnerabilities, Mend now reports 1. Matching on the library name
    alone is what stops a duplicate being created and the original stranded open."""
    conf = _conf()
    azure = _azure_double()
    cache = [{"lodash: 5 vulnerabilities (highest severity is 9.8)":
              {77: {"tags": "Prod/Proj; security vulnerability", "state": "Active"}}}]
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", cache), \
         mock.patch.object(core, "updated_wi", []):
        created, updated, failed = core.create_wi_v3(
            _PROJECT, {("vulnerability", "lodash"): _vuln_entry(_finding())}, [], "Task")

    assert (created, updated, failed) == (0, 1, 0)
    assert _posted(azure) == []
    patches = [c for c in azure.call_args_list if c.kwargs.get("api_type") == "PATCH"]
    assert len(patches) == 1
    assert patches[0].kwargs["api"] == "wit/workitems/77"
    # The cache must now hold the NEW title against the same id, not the stale one as well.
    assert cache == [{"lodash: 1 vulnerabilities (highest severity is 7.4)":
                      {77: {"tags": "Prod/Proj,security vulnerability", "state": "Active"}}}]


def test_a_matched_item_of_the_wrong_type_is_deleted_and_recreated():
    conf = _conf()
    azure = _azure_double(existing_type="Bug")
    cache = [{"License Policy Violation detected in lodash":
              {77: {"tags": "Prod/Proj; license policy violation", "state": "Active"}}}]
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", cache), \
         mock.patch.object(core, "updated_wi", []):
        created, updated, failed = core.create_wi_v3(
            _PROJECT, {("license", "lodash"): _license_entry()}, [], "Task")

    assert (created, updated, failed) == (1, 0, 0)
    assert [c.kwargs["api"] for c in azure.call_args_list
            if c.kwargs.get("api_type") == "DELETE"] == ["wit//workitems/77"]


def test_a_new_item_is_cached_so_the_same_run_does_not_create_it_twice():
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    conf = _conf()
    azure = mock.MagicMock(return_value=({"id": 42, "fields": {"System.State": "New"}}, 0))
    cache, written = [], []
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", cache), \
         mock.patch.object(core, "updated_wi", written):
        core.create_wi_v3(_PROJECT, desired, [], "Task")
    assert cache == [{"lodash: 1 vulnerabilities (highest severity is 7.4)":
                      {42: {"tags": "Prod/Proj,security vulnerability", "state": "New"}}}]
    assert written == [42]


def test_a_failed_write_is_counted_and_does_not_stop_the_rest():
    def _call(**kwargs):
        title = None
        for op in kwargs.get("data") or []:
            if isinstance(op, dict) and op.get("path") == "/fields/System.Title":
                title = op.get("value")
        if title and title.startswith("lodash"):
            return {"message": "TF401320: rule error"}, 1
        return {"id": 42, "fields": {"System.State": "New"}}, 0

    desired = {("vulnerability", "lodash"): _vuln_entry(_finding()),
               ("license", "other-lib"): _license_entry("other-lib")}
    (created, updated, failed), _ = _run(desired, azure=mock.MagicMock(side_effect=_call))
    assert (created, updated, failed) == (1, 0, 1)


def test_an_entry_that_renders_nothing_writes_nothing():
    """A vulnerability entry with no findings must not produce an empty work item."""
    desired = {("vulnerability", "lodash"): _vuln_entry()}
    (created, updated, failed), azure = _run(desired)
    assert (created, updated, failed) == (0, 0, 0)
    assert azure.call_args_list == []


# --- the CVE display URL -----------------------------------------------------------------------

def test_the_cve_url_prefers_an_advisory_reference_over_a_patch_link():
    """vulnerability.references is MIXED -- taking [0] positionally put patch commits in the
    column an operator reads as the advisory."""
    row = source3.render_inputs(_vuln_entry(_finding()))["vulnerabilities"][0]
    assert row["url"] == "https://nvd.nist.gov/vuln/CVE-2020-8203"


def test_the_cve_url_falls_back_to_the_first_non_empty_url():
    finding = _finding()
    finding["vulnerability"]["references"] = [{"url": ""}, {"url": "https://example.com/first"},
                                              {"url": "https://example.com/second"}]
    row = source3.render_inputs(_vuln_entry(finding))["vulnerabilities"][0]
    assert row["url"] == "https://example.com/first"


def test_the_cve_url_is_empty_when_there_are_no_references():
    finding = _finding()
    finding["vulnerability"].pop("references")
    row = source3.render_inputs(_vuln_entry(finding))["vulnerabilities"][0]
    assert row["url"] == ""
