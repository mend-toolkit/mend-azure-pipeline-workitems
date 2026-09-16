"""The unchanged-content skip still fires when the run authenticates with Entra.

Matrix step 3 -- an immediate second run issues no PATCH -- is the step most likely to
regress silently, because the symptom (every work item rewritten every run, and an Azure
process rule dragging operator-set states back to New) looks identical to the content
genuinely differing. Nothing else asserts it under Entra, so a live failure there would
have no test to bisect against.

These drive create_wi_v3 through the REAL transport, doubling requests.request rather than
call_azure_api, so the bearer header, the 401 re-mint and the empty-token guard are all in
the path the comparison runs through.
"""

import json
from unittest import mock

from mend_azure_wi_sync import core

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
PROJECT = {"uuid": "p-1", "name": "Proj", "application_name": "Prod"}


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false", reponame="",
                  routing="false", description="Description", priority="false",
                  azure_area="", azure_project="TestProj", ws_user_key="uk-1",
                  azure_pat="", azure_tenant_id=TENANT, azure_client_id="cid",
                  azure_client_secret="sec", proxy={}, ssl_verify="true",
                  azure_uri="https://dev.azure.com/org/")
    values.update(overrides)
    return mock.MagicMock(**values)


def _finding(cve="CVE-2020-8203", score=7.4, severity="high", lib="lodash"):
    return {
        "component": {"name": lib, "description": "Lodash modular utilities.",
                      "version": "4.17.15", "dependencyType": "Direct",
                      "dependencyFile": "package.json",
                      "localPath": "/app/node_modules/lodash",
                      "references": {"homePage": "https://lodash.com/",
                                     "url": "https://mend.example/library/lodash"}},
        "dependencyContexts": [{"isDirect": True, "directRoots": [
            {"rootLibraryName": "app", "rootLibraryVersion": "1.0.0"}]}],
        "vulnerability": {"name": cve, "description": "Prototype pollution.", "score": score,
                          "severity": severity, "publishDate": "2020-07-15",
                          "references": [{"url": "https://example.com/patch", "patch": True}]},
        "topFix": {"type": "upgrade", "url": "https://example.com/fix",
                   "fixResolution": "Upgrade to 4.17.19", "date": "2020-08-01"},
        "threatAssessment": {"epssPercentage": 12.5, "exploitCodeMaturity": "POC"},
        "reachability": "REACHABLE",
        "findingInfo": {"status": "ACTIVE"},
    }


def _desired():
    return {("vulnerability", "lodash"): {
        "library": "lodash", "kind": "vulnerability",
        "findings": [_finding(), _finding(cve="CVE-2021-23337", score=9.1)],
        "licenses": []}}


class _FakeAzure:
    """Just enough Azure DevOps to create a work item and read it back.

    Holds what the POST wrote, so the second pass compares against the same content a real
    organization would return, not against a hand-written fixture that could drift.
    """

    def __init__(self):
        self.stored = {}
        self.calls = []
        self.next_id = 42

    def __call__(self, api_type, url, json=None, **kwargs):
        self.calls.append((api_type, url, kwargs))
        if api_type == "POST" and "wit/workitems/$" in url:
            wi_id, self.next_id = self.next_id, self.next_id + 1
            self.stored[wi_id] = self._apply({}, json)
            return _response(200, {"id": wi_id, "fields": self.stored[wi_id]})
        if api_type == "PATCH":
            wi_id = _id_from(url)
            self.stored[wi_id] = self._apply(self.stored.get(wi_id, {}), json)
            return _response(200, {"id": wi_id, "fields": self.stored[wi_id]})
        if api_type == "GET":
            wi_id = _id_from(url)
            return _response(200, {"id": wi_id, "fields": self.stored.get(wi_id, {})})
        return _response(200, {})

    @staticmethod
    def _apply(fields, ops):
        fields = dict(fields)
        for op in ops or []:
            path = op.get("path", "")
            if not path.startswith("/fields/"):
                continue
            name = path[len("/fields/"):]
            if op.get("op") == "remove":
                fields.pop(name, None)
            else:
                fields[name] = op.get("value")
        # Azure hands tags back semicolon-delimited whatever was submitted, and reports a
        # work item type the tool compares against wi_type.
        if "System.Tags" in fields:
            fields["System.Tags"] = "; ".join(
                t.strip() for t in str(fields["System.Tags"]).split(",") if t.strip())
        fields.setdefault("System.WorkItemType", "Task")
        fields.setdefault("System.State", "New")
        return fields

    def patches(self):
        return [c for c in self.calls if c[0] == "PATCH"]

    def posts(self):
        return [c for c in self.calls if c[0] == "POST" and "wit/workitems/$" in c[1]]


def _response(status, payload):
    return mock.MagicMock(status_code=status, text=json.dumps(payload))


def _id_from(url):
    return int(url.split("wit/workitems/")[1].split("?")[0].strip("/"))


def _pass(azure, conf, exist_wis):
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "azure_entra_token", return_value="tok-1"), \
         mock.patch.object(core.requests, "request", side_effect=azure), \
         mock.patch.object(core, "exist_wis", exist_wis), \
         mock.patch.object(core, "updated_wi", []):
        return core.create_wi_v3(PROJECT, _desired(), [], "Task")


def _cache_from(azure, project_name="Prod/Proj"):
    """The exist_wis shape get_exist_wi builds, from what the first pass actually wrote."""
    return [{fields["System.Title"]: {wi_id: {"tags": fields.get("System.Tags", ""),
                                              "state": fields.get("System.State", "New")}}}
            for wi_id, fields in azure.stored.items()]


def test_a_second_identical_pass_issues_no_patch_in_entra_mode():
    """Matrix step 3. The whole point is that an Azure process rule cannot reset an
    operator's state on a run that changes nothing."""
    azure, conf = _FakeAzure(), _conf()
    _pass(azure, conf, [])
    assert len(azure.posts()) == 1, "the first pass must create the work item"
    created = len(azure.calls)

    _pass(azure, conf, _cache_from(azure))
    assert azure.patches() == [], "an identical second pass must issue no PATCH"
    assert azure.posts() == azure.posts()[:1], "and must not create a second work item"
    assert len(azure.calls) > created, "the second pass must still read the item back"


def test_the_second_pass_still_carried_the_bearer():
    """Guards against the skip firing for the wrong reason: a pass that never authenticated
    would also issue no PATCH."""
    azure, conf = _FakeAzure(), _conf()
    _pass(azure, conf, [])
    _pass(azure, conf, _cache_from(azure))
    assert all(c[2]["headers"]["Authorization"] == "Bearer tok-1" for c in azure.calls)
    assert all("auth" not in c[2] for c in azure.calls)


def test_a_real_content_change_still_patches_in_entra_mode():
    """The counterpart. A skip that fired unconditionally would pass the test above."""
    azure, conf = _FakeAzure(), _conf()
    _pass(azure, conf, [])
    for fields in azure.stored.values():
        fields["System.Description"] = "<p>something an operator or an older run wrote</p>"

    _pass(azure, conf, _cache_from(azure))
    assert len(azure.patches()) == 1, "changed content must still be written"


def test_the_skip_holds_in_pat_mode_too():
    """Proves the assertion above is about the content comparison, not about Entra."""
    azure = _FakeAzure()
    conf = _conf(azure_pat="a-pat", azure_tenant_id="", azure_client_id="",
                 azure_client_secret="")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core.requests, "request", side_effect=azure), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        core.create_wi_v3(PROJECT, _desired(), [], "Task")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core.requests, "request", side_effect=azure), \
         mock.patch.object(core, "exist_wis", _cache_from(azure)), \
         mock.patch.object(core, "updated_wi", []):
        core.create_wi_v3(PROJECT, _desired(), [], "Task")
    assert azure.patches() == []
    assert all(c[2]["auth"] == ("", "a-pat") for c in azure.calls)
