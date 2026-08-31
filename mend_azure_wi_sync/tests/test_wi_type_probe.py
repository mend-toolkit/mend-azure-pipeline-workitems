"""probe_wi_type: the per-destination read of MEND_AZURETYPE's definition.

Under MEND_ROUTING this runs once per Azure destination instead of once per run against
MEND_AZUREPROJECT, so it has to tolerate a destination that lacks the type (rather than
exit) and it has to stay affordable across 100+ destinations -- see field_meta_cache.
"""
from unittest import mock

import pytest

from mend_azure_wi_sync import core


def _types_payload(fields, name="SCA Issue"):
    return {"value": [{"name": name, "referenceName": "Custom.SCAIssue",
                       "fields": fields}]}


def _field(ref, name="F", always=False):
    return {"referenceName": ref, "name": name, "alwaysRequired": always,
            "defaultValue": None}


def _editable(type_="string"):
    return {"type": type_, "isLocked": False, "isPicklist": False, "readOnly": False}


def _fake_api(types, fields, calls=None):
    """A call_azure_api stand-in: one workitemtypes payload, one dict of field payloads."""
    def _call(api_type=None, api=None, project=None, data=None, version=None, header=None,
              **kwargs):
        if calls is not None:
            calls.append((project, api))
        if api.startswith("wit/workitemtypes"):
            return types
        ref = api.split("wit/fields/")[1]
        return fields.get(ref, ({}, 2))
    return _call


@pytest.fixture(autouse=True)
def _clean_cache():
    core.reset_field_meta_cache()
    yield
    core.reset_field_meta_cache()


def test_the_type_is_matched_case_insensitively_and_its_fields_returned():
    conf = mock.MagicMock(azure_type="sca issue", azure_custom="")
    api = _fake_api((_types_payload([_field("System.Title")]), 0),
                    {"System.Title": (_editable(), 0)})
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", api):
        wi_type, fields = core.probe_wi_type("Platform")

    assert wi_type == "sca issue"
    assert [f["referenceName"] for f in fields] == ["System.Title"]


def test_a_project_without_the_type_returns_no_fields_instead_of_exiting():
    """The routed loop turns this into "skip this destination". load_wi_json turns the same
    answer into exit(-1), because without routing that project IS the destination."""
    conf = mock.MagicMock(azure_type="SCA Issue", azure_custom="")
    api = _fake_api((_types_payload([_field("System.Title")], name="Bug"), 0), {})
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", api):
        assert core.probe_wi_type("Platform") == ("SCA Issue", None)


def test_a_failed_workitemtypes_read_returns_no_fields():
    conf = mock.MagicMock(azure_type="SCA Issue", azure_custom="")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", _fake_api(({}, 2), {})):
        assert core.probe_wi_type("Platform") == ("SCA Issue", None)


def test_field_definitions_are_cached_across_destinations():
    """Field definitions are organization-level in Azure DevOps, so the same referenceName is
    read once for the whole run. Without this, routing costs one call per field per
    destination -- roughly 60 x 107."""
    conf = mock.MagicMock(azure_type="SCA Issue", azure_custom="")
    calls = []
    api = _fake_api((_types_payload([_field("System.Title"), _field("System.State")]), 0),
                    {"System.Title": (_editable(), 0), "System.State": (_editable(), 0)},
                    calls=calls)
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", api):
        for project in ("Platform", "Tools", "Bookkeeping"):
            core.probe_wi_type(project)

    field_calls = [c for c in calls if "wit/fields/" in c[1]]
    assert len(field_calls) == 2
    assert len([c for c in calls if c[1].startswith("wit/workitemtypes")]) == 3


def test_a_field_whose_definition_cannot_be_read_is_dropped_not_inherited():
    """The old loop left `is_add` at the PREVIOUS field's verdict when the read failed, so one
    editable field made the next unreadable one look editable too."""
    conf = mock.MagicMock(azure_type="SCA Issue", azure_custom="")
    api = _fake_api((_types_payload([_field("System.Title"), _field("System.Unreadable")]), 0),
                    {"System.Title": (_editable(), 0)})
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", api):
        _, fields = core.probe_wi_type("Platform")

    assert [f["referenceName"] for f in fields] == ["System.Title"]


def test_custom_and_always_required_fields_survive_an_unreadable_definition():
    conf = mock.MagicMock(azure_type="SCA Issue", azure_custom="")
    api = _fake_api((_types_payload([_field("Custom.Team"),
                                     _field("System.State", always=True),
                                     _field("System.Picklist")]), 0),
                    {"System.Picklist": ({"type": "string", "isLocked": False,
                                          "isPicklist": True, "readOnly": False}, 0)})
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", api):
        _, fields = core.probe_wi_type("Platform")

    assert [f["referenceName"] for f in fields] == ["Custom.Team", "System.State"]


def test_load_wi_json_still_exits_when_the_configured_project_lacks_the_type():
    conf = mock.MagicMock(azure_type="SCA Issue", azure_project="Bookkeeping", azure_custom="")
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "probe_wi_type", return_value=("SCA Issue", None)), \
         pytest.raises(SystemExit):
        core.load_wi_json()


def test_apply_custom_fields_matches_on_reference_name_or_display_name():
    conf = mock.MagicMock(azure_custom="Team::static&MEND:name;Severity::$MEND_SEVERITY")
    fields = [{"referenceName": "Custom.Team", "name": "Team", "defaultValue": None},
              {"referenceName": "Custom.Sev", "name": "Severity", "defaultValue": None}]
    with mock.patch.object(core, "conf", conf):
        out = core.apply_custom_fields(fields)

    assert out[0]["defaultValue"] == "static&MEND:name"
    assert out[1]["defaultValue"] == "$MEND_SEVERITY"


def test_apply_custom_fields_is_a_no_op_without_the_variable():
    conf = mock.MagicMock(azure_custom="")
    fields = [{"referenceName": "Custom.Team", "name": "Team", "defaultValue": "keep"}]
    with mock.patch.object(core, "conf", conf):
        assert core.apply_custom_fields(fields) == fields
