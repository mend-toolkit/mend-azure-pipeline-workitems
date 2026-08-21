from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate


def _conf():
    return mock.MagicMock(azure_type="Task", dependency="false", wsalert="true",
                          enrichment="false", reponame="", routing="false",
                          ws_user_key="uk-123")


def test_a_failed_mend_fetch_verdicts_failed():
    """The regression test for the whole design. If this ever returns OK, every affected
    project's watermark advances past findings that were never read."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", return_value=None):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED
    assert "tok-1" in message
    # A failed fetch never reaches item_failed's success branch, so nothing is recorded
    # for the reverse sync to visit.
    assert core.synced_projects == []


def test_a_genuinely_empty_window_verdicts_ok():
    # get_ingnored_alerts/get_prj_lib_hierarchy/get_prj_licenses/get_lib_locations are
    # defined *inside* create_wi (closures over prj_token), not module attributes, so they
    # cannot be mock.patch.object'd on `core`. fetch_prj_policy returning a project with no
    # libraries (ws_prj[2:] == []) means the create/update loop body never runs, so the only
    # thing that needs to succeed is the underlying call_ws_api plumbing those helpers share.
    conf = _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy", return_value=["Prod", "Proj"]), \
         mock.patch.object(core, "call_ws_api", return_value='{"libraries": []}'):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_OK
    assert "No Task work items" in message
    # create_wi is the only place that resolves (product, project) names for the reverse
    # sync's WIQL tag filter; a successful pass must record exactly (token, "Prod/Proj",
    # the Azure project it wrote to) so update_wi_in_thread can find it.
    assert core.synced_projects == [("tok-1", "Prod/Proj", conf.azure_project)]


def test_an_unexpected_exception_verdicts_failed():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", side_effect=Exception("boom")):
        verdict, _ = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                    "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED


def _prj_el_with_one_cve():
    """A minimally plausible policy-violation library, shaped to reach create_wi_content
    through the real (unmocked) nested closures: one CVE, no license violation, nothing
    ignored, nothing already existing in Azure."""
    return {
        "library": {"url": "http://example.com/lib", "filename": "lib-1.0.jar",
                    "keyUuid": "uuid-1", "keyId": 1},
        "policy": {"name": "[X] Some Policy", "policyMatch": {"type": "VULNERABILITY_SCORE"}},
        "policyViolations": [
            {"violationType": "VULNERABILITY", "issueUuid": "issue-1",
             "vulnerability": {"name": "CVE-2024-1234", "severity": "high",
                                "cvss3_score": 9.8, "score": 9.8, "description": "desc",
                                "url": "http://example.com/cve", "publishDate": "2024-01-01",
                                "topFix": {"url": "http://example.com/fix", "date": "2024-02-01",
                                           "type": "upgrade", "fixResolution": "upgrade to 2.0"}}}
        ],
    }


def _conf_with_library():
    # ws_user_key must be a real string (not a bare MagicMock attribute) so the nested
    # get_prj_lib_hierarchy/get_prj_licenses/get_lib_locations closures' json.dumps(...)
    # calls succeed instead of silently falling back via try_or_error. priority/description/
    # azure_area are pinned to plain falsy/known values so this test exercises the item_failed
    # mechanism and nothing incidental to it.
    return mock.MagicMock(azure_type="Task", dependency="false", wsalert="true",
                          enrichment="false", reponame="", routing="false",
                          ws_user_key="uk-123", description="", priority="false",
                          azure_area="", azure_project="TestProj")


def test_a_failed_work_item_write_verdicts_failed():
    """Covers the per-item failure mechanism itself (the design's central guarantee): a
    non-empty sorted_libs reaches create_wi_content, whose errcode == 1 branch sets
    item_failed. That assignment only reaches this function's return value because of
    `nonlocal item_failed` in create_wi_content -- without it, Python would create a fresh
    local there and this test would silently see VERDICT_OK instead (verified manually by
    deleting that line; see the report for that experiment's output)."""
    conf = _conf_with_library()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _prj_el_with_one_cve()]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api",
                           return_value=({"message": "boom"}, 1)), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED
    assert "No Task work items" in message
    # item_failed was set True inside create_wi_content's errcode==1 branch, and the
    # function still reaches this same end-of-function return (no early exit). Per spec
    # 5.6.1 the append is now unconditional: a forward write failure says nothing about
    # whether this project's *existing* work items changed state, so the reverse sync must
    # still be able to find and visit it. (Previously this asserted `== []`, guarded by an
    # `if not item_failed:` around the append that this task removed.)
    assert core.synced_projects == [("tok-1", "Prod/Proj", conf.azure_project)]


def test_an_azure_api_exception_during_write_verdicts_failed():
    """Covers the third item_failed mutation site: the nested `except Exception` handler
    inside create_wi_content, exercised separately from the errcode == 1 branch above."""
    with mock.patch.object(core, "conf", _conf_with_library()), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _prj_el_with_one_cve()]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api", side_effect=Exception("boom")), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_FAILED


def test_create_wi_calls_enrich_project_for_a_project_with_findings():
    """Guards the replacement for the prepare_enrichment wiring tests this task deleted:
    create_wi must actually call enrich_project for a project with findings, or every
    enabled customer silently gets three columns of '-' with all tests green."""
    conf = _conf_with_library()
    conf.enrichment = "true"
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _prj_el_with_one_cve()]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api", return_value=({}, 0)), \
         mock.patch.object(core, "enrich_project", return_value={}) as enrich, \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")
    enrich.assert_called_once_with("tok-1")


def _custom_field_value(default_value: str):
    """Run one MEND_CUSTOMFIELDS expression through create_wi and return what it resolved to.

    analyze_fields is nested inside create_wi, so it cannot be called directly. This drives
    the real function the way the tests above do and reads the value back out of the PATCH
    body handed to call_azure_api, which is where a custom field actually lands.
    """
    conf = _conf_with_library()
    conf.conf_json.return_value = {"wsurl": "https://saas.mend.io",
                                   "wsuserkey": "SECRET-USER-KEY"}
    captured = []
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _prj_el_with_one_cve()]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api",
                           side_effect=lambda **kw: (captured.append(kw.get("data")),
                                                     ({"id": 1}, 0))[1]), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00",
                       [{"referenceName": "Custom.LeakCanary", "name": "LeakCanary",
                         "defaultValue": default_value}], "Task")
    for body in captured:
        for op in (body or []):
            if op.get("path") == "/fields/Custom.LeakCanary":
                return op.get("value")
    return None


def test_an_unknown_custom_field_variable_does_not_inherit_the_previous_part():
    """A '&'-delimited part naming a variable that no longer exists must resolve to "",
    never to the value of the part before it.

    analyze_fields looks up `var_name` after a `for var_ in varenvs` loop that only assigns
    on a match. `var_name` was never initialised and is never reset per part, so an unmatched
    part silently reused the PREVIOUS part's name and duplicated its value. This was masked
    until 2026-08-21 because `$MEND_EMAIL` matched varenvs.wsemail (absent from conf_json(),
    so it resolved to ""); deleting wsemail with the 2.0 transport made the leak reachable
    for the first time. It matters because the leaked value can be a CREDENTIAL --
    `$MEND_USERKEY&$MEND_EMAIL` rendered the user key TWICE into a work item field.
    MEND_CUSTOMFIELDS syntax is a documented user-facing contract, so this is visible
    behaviour, not an internal detail.

    Fails without the one-line `var_name = ""` init: returns the first value doubled.

    NOTE on the `$MEND_USERKEY` assertion below: it pins PART-INDEPENDENCE -- part two must not
    inherit part one -- and nothing else. It is NOT an endorsement of `$MEND_USERKEY` as an
    intended substitution; writing the org's Mend key into a work item field is an open
    security item on the tracker. Whoever fixes that should change this assertion to whatever
    the new behaviour is (refusal, redaction), not treat this test as blocking them. Any
    variable with a non-empty `conf_json()` value would do here; the key is used only because
    it makes the leak's consequence concrete in the failure message.
    """
    assert _custom_field_value("$MEND_URL") == "https://saas.mend.io"
    assert _custom_field_value("$MEND_NOSUCHVAR") == "" or \
        _custom_field_value("$MEND_NOSUCHVAR") is None
    assert _custom_field_value("$MEND_URL&$MEND_NOSUCHVAR") == "https://saas.mend.io"
    # The credential case, stated separately so a regression names itself in the failure.
    assert _custom_field_value("$MEND_USERKEY&$MEND_NOSUCHVAR") == "SECRET-USER-KEY"
