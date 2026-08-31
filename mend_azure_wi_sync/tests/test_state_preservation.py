"""The update path must not disturb an operator's work item state.

Some Azure DevOps process rules reset `System.State` whenever an item is edited. This tool used
to PATCH every matched work item on every run whether or not anything had changed, so such a rule
dragged an operator's Active item back to New once per run. Two defences are asserted here:
an unchanged item is not written at all, and a genuinely needed write puts the state back.
"""

from unittest import mock

from mend_azure_wi_sync import core

from mend_azure_wi_sync.tests.test_create_wi_v3 import (
    _PROJECT, _conf, _finding, _vuln_entry)


def _ops_of(azure, api_type="PATCH"):
    return [c.kwargs.get("data") for c in azure.call_args_list
            if c.kwargs.get("api_type") == api_type]


def _patch_apis(azure):
    return [c.kwargs.get("api") for c in azure.call_args_list
            if c.kwargs.get("api_type") == "PATCH"]


def _fields_from_ops(ops):
    """Turn the ops this tool would write into the `fields` map Azure would hand back."""
    fields = {"System.WorkItemType": "Task", "System.State": "Active"}
    for op in ops:
        if op.get("path", "").startswith("/fields/"):
            fields[op["path"][len("/fields/"):]] = op.get("value")
    return fields


_DESIRED = {("vulnerability", "lodash"): _vuln_entry(_finding())}
_CACHE_TITLE = "lodash: 1 vulnerabilities (highest severity is 7.4)"


def _cache():
    return [{_CACHE_TITLE: {77: {"tags": "Prod/Proj; security vulnerability",
                                 "state": "Active"}}}]


def _drive(azure, conf=None, desired=None):
    conf = conf or _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", _cache()), \
         mock.patch.object(core, "updated_wi", []):
        return core.create_wi_v3(_PROJECT, desired or _DESIRED, [], "Task")


def _probe_fields():
    """Run once against a double that always accepts, and capture what was written."""
    azure = mock.MagicMock(side_effect=lambda **kw: (
        {"fields": {"System.WorkItemType": "Task", "System.State": "Active"}}, 0)
        if kw.get("api_type") == "GET"
        else ({"id": 77, "fields": {"System.State": "Active"}}, 0))
    _drive(azure)
    return _fields_from_ops(_ops_of(azure)[0])


def _double(fields, get_err=0, patch_result=None, patch_err=0, restore_err=0):
    """A call_azure_api double whose GET returns `fields`."""
    state = {"patches": 0}

    def _call(**kwargs):
        if kwargs.get("api_type") == "GET":
            return ({"fields": dict(fields)}, get_err)
        if kwargs.get("api_type") == "PATCH":
            state["patches"] += 1
            if state["patches"] > 1:
                return ({"id": 77}, restore_err)
            return (patch_result if patch_result is not None
                    else {"id": 77, "fields": {"System.State": "Active"}}, patch_err)
        return ({"id": 77, "fields": {"System.State": "Active"}}, 0)
    return mock.MagicMock(side_effect=_call)


# --- Part 1: no PATCH when nothing changed ----------------------------------------------------

def test_an_unchanged_item_issues_no_patch_at_all():
    azure = _double(_probe_fields())
    created, updated, failed = _drive(azure)
    assert _patch_apis(azure) == []
    assert [c for c in azure.call_args_list if c.kwargs.get("api_type") == "POST"] == []
    assert (created, updated, failed) == (0, 0, 0)


def test_a_changed_title_still_issues_the_patch():
    fields = _probe_fields()
    fields["System.Title"] = "lodash: 5 vulnerabilities (highest severity is 9.8)"
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_a_changed_description_still_issues_the_patch():
    fields = _probe_fields()
    fields["System.Description"] = "<html>something else entirely</html>"
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_a_changed_tag_still_issues_the_patch():
    fields = _probe_fields()
    fields["System.Tags"] = "Prod/Proj; some other tag"
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_a_changed_priority_still_issues_the_patch():
    fields = _probe_fields()
    fields["Microsoft.VSTS.Common.Priority"] = 1
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_tags_differing_only_by_separator_and_case_count_as_unchanged():
    fields = _probe_fields()
    raw = fields["System.Tags"]
    fields["System.Tags"] = "; ".join(t.upper() for t in raw.split(","))
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == []


def test_a_priority_returned_as_a_string_counts_as_unchanged():
    fields = _probe_fields()
    fields["Microsoft.VSTS.Common.Priority"] = str(fields["Microsoft.VSTS.Common.Priority"])
    azure = _double(fields)
    _drive(azure)
    assert _patch_apis(azure) == []


def test_a_failed_get_falls_through_to_the_patch_rather_than_skipping():
    """A transiently failed GET proves nothing, so the write must still happen."""
    azure = _double(_probe_fields(), get_err=2)
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


# --- Part 2: restoring the state after a needed PATCH -----------------------------------------

def _changed_fields():
    fields = _probe_fields()
    fields["System.Description"] = "<html>stale</html>"
    return fields


def test_a_patch_that_leaves_the_state_alone_issues_no_restore_write():
    azure = _double(_changed_fields(),
                    patch_result={"id": 77, "fields": {"System.State": "Active"}})
    _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_a_patch_that_reset_the_state_issues_exactly_one_restore_write():
    azure = _double(_changed_fields(),
                    patch_result={"id": 77, "fields": {"System.State": "New"}})
    created, updated, failed = _drive(azure)
    assert _patch_apis(azure) == ["wit/workitems/77", "wit/workitems/77"]
    assert _ops_of(azure)[1] == [{"op": "replace", "path": "/fields/System.State",
                                 "value": "Active"}]
    assert (created, updated, failed) == (0, 1, 0)


def test_the_post_patch_state_is_read_from_the_patch_response_without_a_second_get():
    azure = _double(_changed_fields(),
                    patch_result={"id": 77, "fields": {"System.State": "New"}})
    _drive(azure)
    gets = [c for c in azure.call_args_list if c.kwargs.get("api_type") == "GET"]
    assert len(gets) == 1


def test_a_patch_response_without_fields_falls_back_to_one_get():
    azure = _double(_changed_fields(), patch_result={"id": 77})
    _drive(azure)
    gets = [c for c in azure.call_args_list if c.kwargs.get("api_type") == "GET"]
    assert len(gets) == 2
    # The follow-up GET reported "Active" as well, so nothing needed restoring.
    assert _patch_apis(azure) == ["wit/workitems/77"]


def test_a_failed_restore_write_is_logged_and_does_not_raise(caplog):
    azure = _double(_changed_fields(),
                    patch_result={"id": 77, "fields": {"System.State": "New"}},
                    restore_err=2)
    with caplog.at_level("WARNING"):
        created, updated, failed = _drive(azure)
    assert (created, updated, failed) == (0, 1, 0)
    assert any("could not be restored" in r.message for r in caplog.records)


def test_a_newly_created_item_never_triggers_a_restore():
    azure = mock.MagicMock(return_value=({"id": 42, "fields": {"System.State": "New"}}, 0))
    conf = _conf()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []):
        created, updated, failed = core.create_wi_v3(_PROJECT, _DESIRED, [], "Task")
    assert (created, updated, failed) == (1, 0, 0)
    assert _patch_apis(azure) == []
