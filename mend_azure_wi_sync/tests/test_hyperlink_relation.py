"""FINDING 3: the Hyperlink relation is the operator's click-through from a work item to the
library's Mend page. The reverse-sync removal deleted it as collateral -- it also used to carry
attributes.comment = "{projectToken},{issueUuid}" for the reverse sync. The link stays; the
comment does not."""
from unittest import mock

from mend_azure_wi_sync import core

LIB_URL = "http://example.com/lib"


def _conf():
    return mock.MagicMock(azure_type="Task", dependency="true", wsalert="true",
                          epss="false", reachability="false", reponame="", routing="false",
                          ws_user_key="uk-123", description="", priority="false",
                          azure_area="", azure_project="TestProj")


def _lib_el():
    return {
        "library": {"url": LIB_URL, "filename": "log4j-core-2.14.1.jar",
                    "keyUuid": "uuid-1", "keyId": 1},
        "policy": {"name": "[X] Some Policy", "policyMatch": {"type": "VULNERABILITY_SCORE"}},
        "policyViolations": [
            {"violationType": "VULNERABILITY", "issueUuid": "issue-1",
             "vulnerability": {"name": "CVE-2024-0001", "severity": "high",
                               "cvss3_score": 9.8, "score": 9.8, "description": "desc",
                               "url": "http://example.com/cve", "publishDate": "2024-01-01",
                               "topFix": {"url": "http://example.com/fix", "date": "2024-02-01",
                                          "type": "upgrade", "fixResolution": "upgrade to 2.0"}}}
        ],
    }


def _create_and_capture():
    posted = []

    def _azure(api_type=None, api=None, data=None, project=None, **kwargs):
        if api_type == "POST":
            posted.append(data)
        return {"id": 42}, 0

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _lib_el()]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api", side_effect=_azure), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "wi_claim_keyid", {}):
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")
    assert posted, "the work item was never created"
    return posted[0]


def _relations(data):
    return [op["value"] for op in data
            if op.get("path") == "/relations/-" and op.get("op") == "add"]


def test_a_created_work_item_carries_a_hyperlink_to_the_library():
    rels = _relations(_create_and_capture())
    assert [r for r in rels if r.get("rel") == "Hyperlink" and r.get("url") == LIB_URL], rels


def test_the_hyperlink_carries_no_token_uuid_comment():
    """That comment existed only for the reverse sync, which is gone and nothing reads it."""
    for rel in _relations(_create_and_capture()):
        comment = str(rel.get("attributes", {}).get("comment", ""))
        assert "," not in comment, rel
        assert "tok-1" not in comment and "issue-1" not in comment, rel
