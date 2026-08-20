from mend_azure_wi_sync import syncstate


def test_parses_our_three_tags_and_ignores_others():
    rows = [{"name": "p", "token": "tok-1", "tags": {
        "azure-wi-lastrun": "2026-08-20 10:00:00",
        "azure-wi-failed": "2026-08-19 10:00:00",
        "azure-wi-revsync": "2026-08-20 09:00:00",
        "azure-project": "Payments",
    }}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {
        "lastrun": "2026-08-20 10:00:00",
        "failed": "2026-08-19 10:00:00",
        "revsync": "2026-08-20 09:00:00",
    }}


def test_a_project_with_no_relevant_tags_is_omitted():
    rows = [{"token": "tok-1", "tags": {"azure-project": "Payments"}}]
    assert syncstate.parse_tag_map(rows) == {}


def test_tag_keys_are_matched_case_insensitively_and_values_stripped():
    rows = [{"token": "tok-1", "tags": {"AZURE-WI-LASTRUN": "  2026-08-20 10:00:00  "}}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {"lastrun": "2026-08-20 10:00:00"}}


def test_malformed_rows_are_skipped_not_fatal():
    rows = [
        "not-a-dict",
        {"tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},   # no token
        {"token": "tok-2", "tags": "not-a-dict"},
        {"token": "", "tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},
        {"token": "tok-3", "tags": {"azure-wi-lastrun": 12345}},  # non-string value
        {"token": "tok-4", "tags": {"azure-wi-lastrun": "2026-08-20 10:00:00"}},
    ]
    assert syncstate.parse_tag_map(rows) == {"tok-4": {"lastrun": "2026-08-20 10:00:00"}}


def test_empty_and_none_input():
    assert syncstate.parse_tag_map([]) == {}
    assert syncstate.parse_tag_map(None) == {}


NOW = "2026-08-20 12:00:00"


def test_clamp_keeps_a_recent_stamp():
    assert syncstate.clamp("2026-08-20 11:00:00", NOW, 720) == "2026-08-20 11:00:00"


def test_clamp_floors_an_old_stamp():
    # 720 hours before NOW is 2026-07-21 12:00:00
    assert syncstate.clamp("2020-01-01 00:00:00", NOW, 720) == "2026-07-21 12:00:00"


def test_clamp_treats_missing_and_unparseable_as_the_floor():
    for bad in (None, "", "not-a-date", "2026-13-45 99:99:99"):
        assert syncstate.clamp(bad, NOW, 720) == "2026-07-21 12:00:00"


def test_window_start_uses_the_projects_own_watermark():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-1", state, NOW, 720, False, 87600) == "2026-08-20 11:00:00"


def test_window_start_for_an_untagged_project_is_the_clamp_not_the_floor():
    """A missing tag means 'I do not know', which must be wide, not narrow. Handing it the
    derived floor would silently skip findings raised while the project was failing."""
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-2", state, NOW, 720, False, 87600) == "2026-07-21 12:00:00"


def test_reset_bypasses_the_tag_map_entirely():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-1", state, NOW, 720, True, 87600) == "2016-08-22 12:00:00"


def test_selection_floor_is_the_newest_watermark():
    state = {
        "tok-1": {"lastrun": "2026-08-20 11:00:00"},
        "tok-2": {"lastrun": "2026-08-18 11:00:00"},
        "tok-3": {"failed": "2026-08-19 11:00:00"},
    }
    assert syncstate.selection_floor(state, "", NOW, 720, False, 87600) == "2026-08-20 11:00:00"


def test_selection_floor_falls_back_to_the_seed_then_to_a_full_window():
    assert syncstate.selection_floor({}, "2026-08-01 00:00:00", NOW, 720, False, 87600) \
        == "2026-08-01 00:00:00"
    assert syncstate.selection_floor({}, "", NOW, 720, False, 87600) == "2016-08-22 12:00:00"


def test_selection_floor_honours_reset():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.selection_floor(state, "", NOW, 720, True, 87600) == "2016-08-22 12:00:00"


def test_selection_unions_modified_with_the_retry_queue():
    state = {
        "tok-failed": {"failed": "2026-08-19 11:00:00"},
        "tok-clean": {"lastrun": "2026-08-20 11:00:00"},
    }
    assert syncstate.build_selection(["tok-modified"], state) == ["tok-failed", "tok-modified"]


def test_selection_deduplicates_and_sorts():
    state = {"tok-a": {"failed": "2026-08-19 11:00:00"}}
    assert syncstate.build_selection(["tok-b", "tok-a"], state) == ["tok-a", "tok-b"]


def test_selection_with_no_state_is_just_the_modified_list():
    assert syncstate.build_selection(["tok-b", "tok-a"], {}) == ["tok-a", "tok-b"]
    assert syncstate.build_selection(None, None) == []


def test_success_advances_the_watermark_then_clears_the_retry_flag():
    """Order matters. Clearing before advancing risks losing the retry hint on a partial
    failure; advancing first means a failed clear self-heals on the next run."""
    assert syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00") == [
        ("save", syncstate.TAG_LASTRUN, "2026-08-20 12:00:00"),
        ("remove", syncstate.TAG_FAILED, ""),
    ]


def test_failure_records_the_retry_flag_and_leaves_the_watermark_alone():
    ops = syncstate.tag_ops(syncstate.VERDICT_FAILED, "2026-08-20 12:00:00")
    assert ops == [("save", syncstate.TAG_FAILED, "2026-08-20 12:00:00")]
    assert not any(key == syncstate.TAG_LASTRUN for _, key, _ in ops)


def test_no_verdict_writes_nothing():
    """An unroutable project never reaches create_wi, so it must never enter the retry queue —
    retrying it cannot succeed until a human fixes its tag."""
    assert syncstate.tag_ops(None, "2026-08-20 12:00:00") == []
    assert syncstate.tag_ops("", "2026-08-20 12:00:00") == []
