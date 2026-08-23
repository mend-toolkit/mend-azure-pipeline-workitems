"""create_wi_v3 -- the 3.0 creation path.

The riskiest thing in this file is not the HTML: it is the TITLES. classify_title decodes a work
item's title back into the (kind, key) pair that closure acts on, so a title this path renders
that classify_title cannot decode is a work item that either never closes or closes something
else. Every title generated here -- dependency mode AND per-CVE mode -- is asserted to
round-trip.
"""

from unittest import mock

from mend_azure_wi_sync import core, source3


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false",
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


def test_per_cve_mode_titles_round_trip_through_classify_title():
    """The per-CVE twin of the dependency-mode contract above, and the whole point of per-CVE
    closure: EVERY title this mode renders must decode back to the key `desired` was built on,
    ("vulnerability", "{cve}|{lib}"). One that does not strands its work item open forever."""
    conf = _conf(dependency="false")
    desired = {
        ("vulnerability", "CVE-2020-8203|lodash"): _vuln_entry(_finding()),
        ("vulnerability", "CVE-2021-23337|lodash"): _vuln_entry(
            _finding(cve="CVE-2021-23337", score=9.1, severity="critical")),
        ("vulnerability", "CVE-2021-44228|log4j-core"): {
            "library": "log4j-core", "kind": "vulnerability", "licenses": [],
            "findings": [_finding(cve="CVE-2021-44228", score=10.0, lib="log4j-core")]},
        # No severity at all, and a non-CVE Mend identifier -- both real, both must still decode.
        ("vulnerability", "WS-2019-0379|lodash"): _vuln_entry(
            _finding(cve="WS-2019-0379", severity="")),
        ("license", "lodash"): _license_entry(),
    }
    with mock.patch.object(core, "conf", conf):
        for (kind, key), entry in desired.items():
            for item in core.render_entry_v3(kind, entry["library"], entry, False):
                assert core.classify_title(item["title"]) == (kind, key), item["title"]


def test_a_rescored_cve_still_decodes_to_the_same_key():
    """The severity word is a wildcard in the key for the same reason the dependency-mode count
    and score are: Mend rescores, and a severity baked into the key orphans the work item."""
    before = "CVE-2021-44228 (Critical) detected in log4j-core"
    after = "CVE-2021-44228 (High) detected in log4j-core"
    assert core.classify_title(before) == ("vulnerability", "CVE-2021-44228|log4j-core")
    assert core.classify_title(after) == core.classify_title(before)


def test_one_cve_in_two_libraries_gives_two_distinct_keys():
    """Why the library is in the key: keying on the CVE alone would collapse these two work items
    into one, and reconciliation would close whichever it saw second."""
    a = core.classify_title("CVE-2021-44228 (Critical) detected in log4j-core")
    b = core.classify_title("CVE-2021-44228 (Critical) detected in log4j-api")
    assert a == ("vulnerability", "CVE-2021-44228|log4j-core")
    assert b == ("vulnerability", "CVE-2021-44228|log4j-api")
    assert a != b


def test_one_cve_in_two_libraries_produces_two_work_items():
    """The end-to-end half of the same guarantee: two entries, two POSTs, two titles."""
    desired = {
        ("vulnerability", "CVE-2021-44228|log4j-core"): {
            "library": "log4j-core", "kind": "vulnerability", "licenses": [],
            "findings": [_finding(cve="CVE-2021-44228", score=10.0, lib="log4j-core")]},
        ("vulnerability", "CVE-2021-44228|log4j-api"): {
            "library": "log4j-api", "kind": "vulnerability", "licenses": [],
            "findings": [_finding(cve="CVE-2021-44228", score=10.0, lib="log4j-api")]},
    }
    (created, updated, failed), azure = _run(desired, conf=_conf(dependency="false"))
    assert (created, updated, failed) == (2, 0, 0)
    titles = sorted(_field(doc, "/fields/System.Title") for doc in _posted(azure))
    assert titles == ["CVE-2021-44228 (High) detected in log4j-api",
                      "CVE-2021-44228 (High) detected in log4j-core"]


def test_a_hand_written_title_is_still_not_adopted_in_per_cve_mode():
    """The per-CVE decoder must not widen classify_title into "anything with brackets". A
    person's own work item carrying a Mend tag must never be adopted and closed."""
    for title in ("Investigate flaky deploy (urgent) detected in prod",
                  "Rotate the signing key",
                  "detected in lodash",
                  "CVE-2021-44228 detected in lodash"):
        assert core.classify_title(title) is None, title


# --- library names containing ":" (Maven coordinates) ----------------------------------------

MAVEN_LIBS = ["org.apache:log4j",
              "com.fasterxml.jackson.core:jackson-databind",
              "weird|lib"]


def test_a_library_name_containing_a_colon_decodes_in_dependency_mode():
    """Maven coordinates are "{group}:{artifact}". Decoding by splitting on the FIRST colon and
    guessing the head returned None for every one of them, so the work item was created and
    updated but could never be closed -- silent, and the exact failure closure exists to fix.
    "|" is the per-CVE key separator and must not confuse the dependency form either."""
    for lib in MAVEN_LIBS:
        title = f"{lib}: 3 vulnerabilities (highest severity is 9.8)"
        assert core.classify_title(title) == ("vulnerability", lib), title


def test_a_library_name_containing_a_colon_decodes_in_per_cve_mode():
    for lib in MAVEN_LIBS:
        title = f"CVE-2021-44228 (Critical) detected in {lib}"
        assert core.classify_title(title) == ("vulnerability", f"CVE-2021-44228|{lib}"), title


def test_colon_library_round_trips_from_desired_through_the_title_and_back_dependency_mode():
    """The full loop for a Maven coordinate: the key source3 builds `desired` on -> the title
    create_wi_v3 renders -> the key classify_title decodes. The first and last must be equal or
    reconciliation reads the live work item as an orphan and closes it.

    Dependency mode keys on the ROOT library (Task 1: root-library grouping), so the finding's own
    root is set to the colon-bearing coordinate itself -- a direct Maven dependency is its own
    root -- rather than relying on the `_finding` helper's default "app" root."""
    conf = _conf()
    finding = _finding(cve="CVE-2021-44228", score=10.0, lib="org.apache:log4j")
    finding["dependencyContexts"] = [{"isDirect": True, "directRoots": [
        {"rootLibraryName": "org.apache:log4j", "rootLibraryVersion": "1.0.0"}]}]
    entries, _ = source3.normalise_findings([finding], 0.0, per_cve=False)
    assert list(entries) == ["org.apache:log4j"]
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "org.apache:log4j",
                                     entries["org.apache:log4j"], False)
    assert items[0]["title"] == \
        "org.apache:log4j: 1 vulnerabilities (highest severity is 10.0)"
    assert core.classify_title(items[0]["title"]) == ("vulnerability", "org.apache:log4j")


def test_colon_library_round_trips_from_desired_through_the_title_and_back_per_cve_mode():
    conf = _conf(dependency="false")
    finding = _finding(cve="CVE-2021-44228", score=10.0, lib="org.apache:log4j")
    entries, _ = source3.normalise_findings([finding], 0.0, per_cve=True)
    assert list(entries) == ["CVE-2021-44228|org.apache:log4j"]
    with mock.patch.object(core, "conf", conf):
        items = core.render_entry_v3("vulnerability", "org.apache:log4j",
                                     entries["CVE-2021-44228|org.apache:log4j"], False)
    assert items[0]["title"] == "CVE-2021-44228 (High) detected in org.apache:log4j"
    assert core.classify_title(items[0]["title"]) == \
        ("vulnerability", "CVE-2021-44228|org.apache:log4j")


def test_the_dependency_form_is_decoded_before_the_per_cve_form():
    """A title that could parse as both must resolve as the dependency form: its tail is the more
    specific pattern, and decoding it as per-CVE invented a library that matches nothing."""
    title = "a-b (c) detected in log4j: 2 vulnerabilities (highest severity is 9.8)"
    assert core.classify_title(title) == ("vulnerability", "a-b (c) detected in log4j")


# --- rendering -------------------------------------------------------------------------------

def test_dependency_mode_renders_one_table_row_per_cve():
    desired = {("vulnerability", "lodash"): _vuln_entry(
        _finding(), _finding(cve="CVE-2021-23337", score=9.1))}
    (created, updated, failed), azure = _run(desired)
    assert (created, updated, failed) == (1, 0, 0)
    desc = _field(_posted(azure)[0], "/fields/System.Description")
    assert desc.count("<tr>") == 3            # header + one row per CVE
    assert "CVE-2020-8203" in desc and "CVE-2021-23337" in desc


def test_epss_and_exploit_always_render():
    """MEND_EPSS is gone: both values arrive inline with the 3.0 finding, so there is nothing
    to spare an org by hiding them."""
    desired = {("vulnerability", "lodash"): _vuln_entry(_finding())}
    (_, _, _), azure = _run(desired)
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
