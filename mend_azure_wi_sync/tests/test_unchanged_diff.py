"""Why an "unchanged" work item still gets written.

wi_content_unchanged returns a bare bool, so when it says "changed" on every work item in a run
there is nothing in the logs to say WHICH field it thinks moved. That is exactly the state this
bug was reported in. wi_content_diff names them, and wi_content_unchanged is now defined in terms
of it, so the two can never disagree.

The comparison's bias stays unchanged: anything it cannot prove identical counts as a difference,
because writing twice is harmless and skipping a real change is not.
"""

from mend_azure_wi_sync import core


def _ops(**fields):
    return [{"op": "replace", "path": f"/fields/{name}", "value": value}
            for name, value in fields.items()]


def test_no_differences_when_every_field_matches():
    ops = _ops(**{"System.Title": "lodash: 2 vulnerabilities", "System.Tags": "Mend,Legal"})
    fields = {"System.Title": "lodash: 2 vulnerabilities", "System.Tags": "Mend; Legal"}
    assert core.wi_content_diff(ops, fields) == []
    assert core.wi_content_unchanged(ops, fields) is True


def test_the_differing_field_is_named():
    ops = _ops(**{"System.Title": "new title", "System.Tags": "Mend"})
    fields = {"System.Title": "old title", "System.Tags": "Mend"}
    assert core.wi_content_diff(ops, fields) == ["System.Title"]
    assert core.wi_content_unchanged(ops, fields) is False


def test_every_differing_field_is_named_not_just_the_first():
    """A run that rewrites everything needs the whole story in one pass, not one field per fix."""
    ops = _ops(**{"System.Title": "new", "System.Description": "<p>new</p>",
                  "Microsoft.VSTS.Common.Priority": 2})
    fields = {"System.Title": "old", "System.Description": "<p>old</p>",
              "Microsoft.VSTS.Common.Priority": 3}
    assert core.wi_content_diff(ops, fields) == [
        "System.Title", "System.Description", "Microsoft.VSTS.Common.Priority"]


def test_a_field_azure_never_returned_is_named_as_missing():
    """Azure omits an empty field from the GET entirely. That is indistinguishable from a real
    change, so it counts as one -- but the log must not read as though the values differed."""
    ops = _ops(**{"Custom.MendScore": "9.8"})
    assert core.wi_content_diff(ops, {"System.Title": "t"}) == ["Custom.MendScore (absent)"]


def test_an_op_outside_fields_stops_the_comparison_and_says_so():
    ops = [{"op": "add", "path": "/relations/-", "value": {"rel": "Hyperlink"}}]
    assert core.wi_content_diff(ops, {"System.Title": "t"}) == ["/relations/- (unrecognised op)"]
    assert core.wi_content_unchanged(ops, {"System.Title": "t"}) is False


def test_an_empty_fields_dict_is_reported_as_an_unreadable_work_item():
    """A failed or empty GET proves nothing about what Azure holds."""
    assert core.wi_content_diff(_ops(**{"System.Title": "t"}), {}) == ["(no fields returned)"]
    assert core.wi_content_unchanged(_ops(**{"System.Title": "t"}), {}) is False


def test_tags_still_compare_case_insensitively_and_across_delimiters():
    ops = _ops(**{"System.Tags": "mend,legal"})
    assert core.wi_content_diff(ops, {"System.Tags": "Legal; Mend"}) == []


def test_priority_still_compares_numerically():
    assert core.wi_content_diff(_ops(**{"Microsoft.VSTS.Common.Priority": 3}),
                               {"Microsoft.VSTS.Common.Priority": "3"}) == []


def test_a_remove_op_matches_a_field_azure_already_holds_nothing_for():
    ops = [{"op": "remove", "path": "/fields/Custom.Gone"}]
    assert core.wi_content_diff(ops, {"System.Title": "t"}) == []
    assert core.wi_content_diff(ops, {"System.Title": "t", "Custom.Gone": "still here"}) \
        == ["Custom.Gone"]


def test_markup_azure_rewrote_is_not_a_difference_but_content_still_is():
    """This REVERSES an earlier decision, deliberately. It used to compare the description as
    written, on the grounds that normalising HTML could hide a real change. Live runs then
    confirmed Azure DevOps rewrites the HTML it stores, so that compare never matched and nothing
    was ever skipped -- the exact bug the skip exists to prevent. Content is now compared via
    canonical_html (visible text + every URL); see test_description_compare.py."""
    ops = _ops(**{"System.Description": "<details><summary>x</summary></details>"})
    fields = {"System.Description": "<div><details><summary>x</summary></details></div>"}
    assert core.wi_content_diff(ops, fields) == []
    changed = _ops(**{"System.Description": "<details><summary>y</summary></details>"})
    assert core.wi_content_diff(changed, fields) == ["System.Description"]


# ------------------------------------------------------- the second silent path to a full rewrite
#
# The skip requires err_ == 0 from the pre-write GET, and rightly so: a failed GET proves nothing
# about what Azure holds. But it logged NOTHING when the GET failed, so "every item is rewritten
# because the content genuinely differs" and "every item is rewritten because the GET never
# succeeded" looked identical in a log. They need different fixes.

from unittest import mock


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false", reponame="",
                  routing="false", description="Description", priority="false", azure_area="",
                  azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _item():
    return {"title": "lodash: 1 vulnerabilities (highest severity is 7.4)", "desc": "<p>x</p>",
            "score": "7.4", "exact": False, "library": "lodash", "source": {},
            "priority": 3}


def test_a_failed_pre_write_get_says_so_rather_than_silently_rewriting(caplog):
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "check_wi_id_matching", return_value=42), \
         mock.patch.object(core, "call_azure_api") as api:
        # the pre-write GET fails; the PATCH that follows succeeds
        api.side_effect = [({"message": "throttled"}, 1), ({"id": 42}, 0)]
        with caplog.at_level("WARNING"):
            outcome = core.write_wi_v3(_item(), ["Mend"], "", [], "Task", "Prod/api")
    assert outcome == "updated"
    assert "42" in caplog.text
    assert "could not be read" in caplog.text.lower()


def test_a_successful_get_that_matches_still_skips_and_logs_nothing_alarming(caplog):
    fields = {"System.Title": "lodash: 1 vulnerabilities (highest severity is 7.4)",
              "System.Description": "<p>x</p>", "System.Tags": "Mend",
              "Microsoft.VSTS.Common.Priority": 3, "System.WorkItemType": "Task",
              "System.State": "Active"}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "check_wi_id_matching", return_value=42), \
         mock.patch.object(core, "call_azure_api", return_value=({"fields": fields}, 0)):
        with caplog.at_level("WARNING"):
            outcome = core.write_wi_v3(_item(), ["Mend"], "", [], "Task", "Prod/api")
    assert outcome == "unchanged"
    assert caplog.text == ""
