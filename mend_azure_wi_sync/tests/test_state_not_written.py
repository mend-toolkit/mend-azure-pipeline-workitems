"""System.State is never written by an UPDATE, and never compared.

load_wi_json keeps every field Azure reports as alwaysRequired, and System.State is alwaysRequired
in most process templates. So it arrives in cstm_flds carrying Azure's DEFAULT value ("New", "To
Do"), and write_wi_v3's custom-field loop then appends it to every write. Two consequences, both
observed live:

  1. The unchanged-check always saw a difference -- Azure holds "Active", the run would write
     "New" -- so every work item was rewritten every run.
  2. The PATCH actually reset the state. restore_wi_state exists to undo exactly that, which is
     treating the symptom: the write should never have happened.

State transitions are not this tool's business on an update -- reconciliation owns them, via
apply_close / apply_reopen and MEND_CLOSEDSTATE / MEND_REOPENSTATE. System.Reason travels with
State in the same state machine and is excluded for the same reason.

CREATE is different and still writes them: the field is alwaysRequired, so it may be required in
the create payload, and a brand-new item has no operator-set state to trample.
"""

from unittest import mock

from mend_azure_wi_sync import core


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false", reponame="",
                  routing="false", description="Description", priority="false", azure_area="",
                  azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _item():
    return {"title": "lodash: 1 vulnerabilities (highest severity is 7.4)", "desc": "<p>x</p>",
            "score": "7.4", "exact": False, "library": "lodash", "source": {}, "priority": 3}


# System.State as load_wi_json hands it over: alwaysRequired, with Azure's default value.
STATE_FIELD = {"referenceName": "System.State", "name": "State", "defaultValue": "New"}
REASON_FIELD = {"referenceName": "System.Reason", "name": "Reason", "defaultValue": "New"}
CUSTOM_FIELD = {"referenceName": "Custom.Team", "name": "Team", "defaultValue": "Platform"}


def _paths(call):
    return [op["path"] for op in call.kwargs["data"]]


def test_an_update_does_not_write_system_state_or_reason():
    fields = {"System.Title": "lodash: 1 vulnerabilities (highest severity is 7.4)",
              "System.Description": "<p>different</p>", "System.Tags": "Mend",
              "Microsoft.VSTS.Common.Priority": 3, "System.WorkItemType": "Task",
              "System.State": "Active", "Custom.Team": "Platform"}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "check_wi_id_matching", return_value=42), \
         mock.patch.object(core, "call_azure_api") as api:
        api.side_effect = [({"fields": fields}, 0), ({"id": 42, "fields": fields}, 0),
                           ({"id": 42}, 0)]
        outcome = core.write_wi_v3(_item(), ["Mend"], "",
                                   [STATE_FIELD, REASON_FIELD, CUSTOM_FIELD], "Task", "Prod/api")
    assert outcome == "updated"
    patch_paths = _paths(api.call_args_list[1])
    assert "/fields/System.State" not in patch_paths
    assert "/fields/System.Reason" not in patch_paths
    # a genuine custom field is untouched by the exclusion
    assert "/fields/Custom.Team" in patch_paths


def test_a_create_still_writes_them_because_the_field_is_always_required():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "check_wi_id_matching", return_value=0), \
         mock.patch.object(core, "call_azure_api") as api:
        api.return_value = ({"id": 99, "fields": {}}, 0)
        outcome = core.write_wi_v3(_item(), ["Mend"], "", [STATE_FIELD, CUSTOM_FIELD],
                                   "Task", "Prod/api")
    assert outcome == "created"
    assert "/fields/System.State" in _paths(api.call_args_list[0])


def test_a_work_item_differing_only_in_state_is_now_left_alone():
    """The whole point: an item whose content matches is skipped, so the PATCH that would have
    reset its state is never issued and there is nothing to restore."""
    fields = {"System.Title": "lodash: 1 vulnerabilities (highest severity is 7.4)",
              "System.Description": "<p>x</p>", "System.Tags": "Mend",
              "Microsoft.VSTS.Common.Priority": 3, "System.WorkItemType": "Task",
              "System.State": "Active"}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "check_wi_id_matching", return_value=42), \
         mock.patch.object(core, "call_azure_api") as api:
        api.return_value = ({"fields": fields}, 0)
        outcome = core.write_wi_v3(_item(), ["Mend"], "", [STATE_FIELD], "Task", "Prod/api")
    assert outcome == "unchanged"
    # exactly one call: the pre-write GET. No PATCH, so no state reset and no restore.
    assert api.call_count == 1


def test_the_comparison_ignores_state_even_if_some_path_writes_it():
    """Belt and braces: an operator can name System.State in MEND_CUSTOMFIELDS explicitly, and a
    state difference must never be what forces a rewrite."""
    ops = [{"op": "replace", "path": "/fields/System.State", "value": "New"},
           {"op": "replace", "path": "/fields/System.Title", "value": "same"}]
    assert core.wi_content_diff(ops, {"System.State": "Active", "System.Title": "same"}) == []


def test_the_comparison_still_reports_a_real_change_alongside_an_ignored_state():
    ops = [{"op": "replace", "path": "/fields/System.State", "value": "New"},
           {"op": "replace", "path": "/fields/System.Title", "value": "new title"}]
    assert core.wi_content_diff(ops, {"System.State": "Active", "System.Title": "old title"}) \
        == ["System.Title"]
