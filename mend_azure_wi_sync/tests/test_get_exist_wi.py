from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import Tags


def test_all_tags_are_distinct_and_non_empty():
    tags = Tags.all_tags()
    assert len(tags) == len(set(tags))
    assert all(t for t in tags)
    assert "security vulnerability" in tags
    assert "license policy violation" in tags


def test_predicate_covers_every_tag_value():
    predicate = core.mend_tag_predicate()
    for tag in Tags.all_tags():
        assert f'[System.Tags] CONTAINS "{tag}"' in predicate


def test_predicate_is_an_or_expression():
    predicate = core.mend_tag_predicate()
    assert predicate.count(" OR ") == len(Tags.all_tags()) - 1


def test_no_tag_value_would_break_wiql_quoting():
    """Tag values are interpolated into a double-quoted WIQL literal."""
    for tag in Tags.all_tags():
        assert '"' not in tag


from unittest import mock


def test_project_with_no_mend_work_items_returns_empty_not_none():
    """A brand-new project must bootstrap, not abort.

    Regression guard for the off-by-one at core.py:362, which issued one batch too many
    when the id count was an exact multiple of 200 — including zero. With batch failures
    made fatal, that empty {"ids": []} call could abort every run forever.
    """
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Platform")), \
         mock.patch.object(core, "call_azure_api",
                           return_value=({"workItems": []}, 0)) as api:
        result = core.get_exist_wi()

    assert result == []                 # not None — an empty project is not a failure
    assert api.call_count == 1          # the WIQL page only; no hydration batch


def test_exact_multiple_of_batch_size_issues_no_empty_batch():
    """200 ids must produce exactly one hydration call, not two."""
    ids_page = {"workItems": [{"id": n} for n in range(1, 201)]}
    batch = {"value": [{"fields": {"System.Id": n, "System.Title": f"t{n}",
                                   "System.Tags": "ProductX/api; security vulnerability"}}
                       for n in range(1, 201)]}
    with mock.patch.object(core, "conf", mock.MagicMock(azure_project="Platform")), \
         mock.patch.object(core, "call_azure_api",
                           side_effect=[(ids_page, 0),           # WIQL page 1
                                        ({"workItems": []}, 0),  # WIQL page 2 (ends loop)
                                        (batch, 0)]) as api:
        result = core.get_exist_wi()

    assert len(result) == 200
    assert api.call_count == 3          # 2 WIQL + 1 batch; a 4th would be the empty batch
