from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import syncstate

# call_ws_api is mocked with a single fixed return value shared by every Mend call create_wi
# makes for a project (getProjectHierarchy, getProjectLicenses, getProjectLibraryLocations,
# getProjectLibraryDependencies, ...). Providing empty "libraries"/"libraryLocations" arrays
# (rather than "{}") is required so the nested get_pathes/get_lib_lic closures iterate an
# empty list instead of raising on a missing key -- the same shape test_create_wi_verdict.py
# uses for the same reason.
WS_RESPONSE = '{"libraries": [], "libraryLocations": []}'


def _conf():
    # ws_user_key must be a real string (not a bare MagicMock attribute) so the nested
    # closures' json.dumps(...) calls succeed instead of silently falling back via
    # try_or_error to a value that later breaks type assumptions elsewhere. priority and
    # azure_area are pinned so create_wi_content doesn't try to call the unmocked
    # create_area() or exercise MagicMock truthiness. Mirrors test_create_wi_verdict.py's
    # _conf_with_library().
    return mock.MagicMock(azure_type="Task", dependency="false", wsalert="true",
                          enrichment="false", reponame="", routing="false",
                          azure_project="Book", description="Description",
                          ws_user_key="uk-123", priority="false", azure_area="")


def _issue(policy_type, key_id):
    """A minimally plausible policy-violation library, shaped to reach create_wi_content
    through the real (unmocked) nested closures regardless of which of the eight policy
    match types it carries -- same intent as test_create_wi_verdict.py's
    _prj_el_with_one_cve(), generalized to any type (only LICENSE gets the LICENSE
    violationType/shape; every other type, supported or not, looks like a real vulnerability
    violation, since policy.policyMatch.type is the only thing the guard inspects)."""
    violation_type = "LICENSE" if policy_type == "LICENSE" else "VULNERABILITY"
    violation = {"violationType": violation_type, "issueUuid": f"iss-{key_id}"}
    if violation_type == "VULNERABILITY":
        violation["vulnerability"] = {
            "name": "CVE-2024-1234", "severity": "high", "cvss3_score": 9.8, "score": 9.8,
            "description": "desc", "url": "http://example.com/cve",
            "publishDate": "2024-01-01",
            "topFix": {"url": "http://example.com/fix", "date": "2024-02-01",
                       "type": "upgrade", "fixResolution": "upgrade to 2.0"},
        }
    return {
        "policy": {"name": "[x] p", "policyMatch": {"type": policy_type}, "enabled": True},
        "library": {"keyId": key_id, "keyUuid": f"uuid-{key_id}", "filename": f"lib{key_id}",
                    "url": "http://lib"},
        "policyViolations": [violation],
    }


def test_an_unsupported_policy_type_creates_no_work_item(caplog):
    """The reverse sync only ever selects LICENSE and VULNERABILITY_SCORE, so work items for
    the other six types can never round-trip. Creating them orphans them."""
    unsupported = ["Prod", "Proj", _issue("LIBRARY_STALENESS", 1)]
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", return_value=unsupported), \
         mock.patch.object(core, "call_azure_api", return_value=({"id": 7}, 0)) as azure, \
         mock.patch.object(core, "call_ws_api", return_value=WS_RESPONSE), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         caplog.at_level("INFO"):
        verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                          "2026-08-20 12:00:00", [], "Task")
    assert verdict == syncstate.VERDICT_OK
    assert not any(c.kwargs.get("api_type") == "POST" for c in azure.call_args_list)
    assert any("LIBRARY_STALENESS" in r.getMessage() for r in caplog.records)


def test_supported_types_are_still_processed():
    for supported in ("LICENSE", "VULNERABILITY_SCORE"):
        payload = ["Prod", "Proj", _issue(supported, 1)]
        with mock.patch.object(core, "conf", _conf()), \
             mock.patch.object(core, "fetch_prj_policy", return_value=payload), \
             mock.patch.object(core, "call_azure_api",
                               return_value=({"id": 7}, 0)) as azure, \
             mock.patch.object(core, "call_ws_api", return_value=WS_RESPONSE), \
             mock.patch.object(core, "exist_wis", []), \
             mock.patch.object(core, "updated_wi", []):
            verdict, message = core.create_wi("tok-1", "2026-08-01 00:00:00",
                                              "2026-08-20 12:00:00", [], "Task")
        assert azure.call_count > 0, f"{supported} should still be processed: {message}"
        assert verdict == syncstate.VERDICT_OK, message


def test_the_skip_is_logged_once_per_project_not_once_per_violation(caplog):
    """A project with many unsupported violations must not emit a line for each."""
    many = ["Prod", "Proj"] + [_issue("GAV_REGEX", i) for i in range(1, 6)]
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy", return_value=many), \
         mock.patch.object(core, "call_azure_api", return_value=({"id": 7}, 0)), \
         mock.patch.object(core, "call_ws_api", return_value=WS_RESPONSE), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         caplog.at_level("INFO"):
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")
    skips = [r for r in caplog.records if "unsupported policy" in r.getMessage().lower()]
    assert len(skips) == 1
    assert "5" in skips[0].getMessage()
