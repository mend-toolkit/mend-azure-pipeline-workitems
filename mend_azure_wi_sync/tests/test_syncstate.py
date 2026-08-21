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


def test_clamp_floors_an_old_stamp_because_it_is_the_derived_value_primitive():
    """clamp() still floors — it is what the selection floor and the MEND_RESET window are
    built from, where flooring only bounds cost. What changed is that no per-project window
    goes through it any more: see keep_or_clamp below."""
    # 720 hours before NOW is 2026-07-21 12:00:00
    assert syncstate.clamp("2020-01-01 00:00:00", NOW, 720) == "2026-07-21 12:00:00"


def test_keep_or_clamp_never_moves_a_present_watermark_forward():
    """A stored watermark is a fact about what has been read, not a cost knob. Flooring it
    would skip everything between it and the floor, and the next OK verdict would write
    lastrun = todate over that gap, losing it permanently."""
    assert syncstate.keep_or_clamp("2020-01-01 00:00:00", NOW, 720) == "2020-01-01 00:00:00"


def test_keep_or_clamp_floors_only_an_absent_or_unparseable_watermark():
    for bad in (None, "", "not-a-date", "2026-13-45 99:99:99"):
        assert syncstate.keep_or_clamp(bad, NOW, 720) == "2026-07-21 12:00:00"


def test_is_stale_flags_only_a_present_watermark_older_than_the_lookback():
    assert syncstate.is_stale("2020-01-01 00:00:00", NOW, 720) is True
    assert syncstate.is_stale("2026-08-20 11:00:00", NOW, 720) is False
    # Absent is not stale: it goes to the clamp, which is already the widest sane window.
    assert syncstate.is_stale(None, NOW, 720) is False
    assert syncstate.is_stale("not-a-date", NOW, 720) is False


def test_clamp_treats_missing_and_unparseable_as_the_floor():
    for bad in (None, "", "not-a-date", "2026-13-45 99:99:99"):
        assert syncstate.clamp(bad, NOW, 720) == "2026-07-21 12:00:00"


def test_window_start_uses_the_projects_own_watermark():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-1", state, NOW, 720, False, 87600) == "2026-08-20 11:00:00"


def test_window_start_honours_a_stale_watermark_instead_of_narrowing_it():
    """The persistently-failing project: its work item writes are rejected every run so its
    watermark freezes. On the run where the operator finally fixes the cause, a narrowed
    window would silently drop everything raised since the freeze."""
    state = {"tok-1": {"lastrun": "2026-06-01 00:00:00"}}
    assert syncstate.window_start("tok-1", state, NOW, 720, False, 87600) == "2026-06-01 00:00:00"


def test_window_start_for_an_untagged_project_is_the_clamp_not_the_floor():
    """A missing tag means 'I do not know', which must be wide, not narrow. Handing it the
    derived floor would silently skip findings raised while the project was failing."""
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-2", state, NOW, 720, False, 87600) == "2026-07-21 12:00:00"


def test_reset_bypasses_the_tag_map_entirely():
    state = {"tok-1": {"lastrun": "2026-08-20 11:00:00"}}
    assert syncstate.window_start("tok-1", state, NOW, 720, True, 87600) == "2016-08-22 12:00:00"


def test_selection_floor_is_the_oldest_watermark():
    """Was max(). max() is only safe if every project that did not succeed carries a tag, and a
    project selected but never reached carries none — so max() would advance the floor past a
    window nobody read. min() converges on max() after one full pass anyway."""
    state = {
        "tok-1": {"lastrun": "2026-08-20 11:00:00"},
        "tok-2": {"lastrun": "2026-08-18 11:00:00"},
        "tok-3": {"failed": "2026-08-19 11:00:00"},
    }
    assert syncstate.selection_floor(state, "", NOW, 720, False, 87600) == "2026-08-18 11:00:00"


def test_a_truncated_run_does_not_let_the_floor_skip_the_project_it_never_reached():
    """The scenario the old max() lost: the run processed tok-done and was killed (timeout,
    cancellation, OOM) before tok-untouched. tok-untouched got no tag of any kind, so nothing
    unions it back in — only the floor can still select it, and only if the floor stayed
    behind its last scan."""
    state = {
        "tok-done": {"lastrun": "2026-08-20 11:00:00"},
        "tok-untouched": {"lastrun": "2026-08-14 09:00:00"},
    }
    assert syncstate.selection_floor(state, "", NOW, 720, False, 87600) == "2026-08-14 09:00:00"


def test_the_selection_floor_is_still_bounded_by_the_lookback():
    """min() over a project frozen years ago must not turn the org sweep into a 10-year query:
    a project last modified before its own window start cannot yield anything its fetch would
    return, so selecting it costs ~5 Mend calls and a tag write for nothing."""
    state = {"tok-frozen": {"lastrun": "2020-01-01 00:00:00"}}
    assert syncstate.selection_floor(state, "", NOW, 720, False, 87600) == "2026-07-21 12:00:00"


def test_selection_floor_falls_back_to_the_seed_then_to_the_lookback():
    assert syncstate.selection_floor({}, "2026-08-01 00:00:00", NOW, 720, False, 87600) \
        == "2026-08-01 00:00:00"
    # Cold start with no seed: MEND_MAXLOOKBACK, not the 10-year reset window. Every untagged
    # project's own window is todate - max_hours, so a wider sweep can only select projects
    # whose fetch is guaranteed to return nothing.
    assert syncstate.selection_floor({}, "", NOW, 720, False, 87600) == "2026-07-21 12:00:00"


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
    failure; advancing first means a failed clear self-heals on the next run. The remove now
    carries the value the org sweep read back, since removeProjectTag may match on it."""
    assert syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00",
                             "2026-08-19 11:00:00") == [
        ("save", syncstate.TAG_LASTRUN, "2026-08-20 12:00:00"),
        ("remove", syncstate.TAG_FAILED, "2026-08-19 11:00:00"),
    ]


def test_success_on_a_healthy_project_does_not_remove_a_tag_that_is_not_there():
    """The removeProjectTag-on-an-absent-key call was unconditional. If it errors, the
    once-per-run warning fires on every healthy run: the run falsely reports its sync state
    unavailable AND the warning budget is spent, masking every genuine save failure after it."""
    for absent in ("", "   ", None):
        assert syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00", absent) == [
            ("save", syncstate.TAG_LASTRUN, "2026-08-20 12:00:00"),
        ]
    assert syncstate.tag_ops(syncstate.VERDICT_OK, "2026-08-20 12:00:00") == [
        ("save", syncstate.TAG_LASTRUN, "2026-08-20 12:00:00"),
    ]


def test_failed_stamp_reads_the_stored_retry_value_for_one_project():
    state = {"tok-1": {"failed": "2026-08-19 11:00:00"}, "tok-2": {"lastrun": "x"}}
    assert syncstate.failed_stamp("tok-1", state) == "2026-08-19 11:00:00"
    assert syncstate.failed_stamp("tok-2", state) == ""
    assert syncstate.failed_stamp("tok-absent", state) == ""
    assert syncstate.failed_stamp("tok-1", None) == ""


def test_failure_records_the_retry_flag_and_leaves_the_watermark_alone():
    ops = syncstate.tag_ops(syncstate.VERDICT_FAILED, "2026-08-20 12:00:00")
    assert ops == [("save", syncstate.TAG_FAILED, "2026-08-20 12:00:00")]
    assert not any(key == syncstate.TAG_LASTRUN for _, key, _ in ops)


def test_no_verdict_writes_nothing():
    """An unroutable project never reaches create_wi, so it must never enter the retry queue —
    retrying it cannot succeed until a human fixes its tag."""
    assert syncstate.tag_ops(None, "2026-08-20 12:00:00") == []
    assert syncstate.tag_ops("", "2026-08-20 12:00:00") == []


def test_the_project_tag_is_parsed_into_the_state_map():
    rows = [{"token": "tok-1", "tags": {"azure-wi-project": "Payments|Prod/Proj"}}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {"project": "Payments|Prod/Proj"}}


# --- getOrganizationProjectTags returns list-valued tags (verified live 2026-08-21) ---
# The 1.4 sweep's real row shape is {"name":…, "token":…, "tags": {key: [value, …]}} — the
# tags container is a dict, but every value is a LIST of strings. Requiring str values here
# skipped every tag, so the whole org parsed to {} while the writes were succeeding, and
# core's shape guard reported a mismatch that did not exist.

def test_list_valued_tags_are_read_the_way_the_1_4_api_returns_them():
    rows = [{"name": "Test Workitems_master", "token": "tok-1", "tags": {
        "azure-wi-project": ["Test Pipeline Workitems|Test Pipeline Workitems/Test Workitems_master"],
        "test": ["test"],
        "azure-branch": ["refs/heads/master"],
        "azure-project": ["Test Pipeline Workitems"],
        "azure-wi-lastrun": ["2026-08-21 14:36:34"],
    }}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {
        "lastrun": "2026-08-21 14:36:34",
        "project": "Test Pipeline Workitems|Test Pipeline Workitems/Test Workitems_master",
    }}


def test_list_and_scalar_tag_values_are_both_accepted():
    """Only the list form is observed live, but the scalar form is what the docs imply and
    what every existing test asserts. Both must keep working."""
    rows = [{"token": "tok-1", "tags": {"azure-wi-lastrun": ["  2026-08-20 10:00:00  "]}},
            {"token": "tok-2", "tags": {"azure-wi-lastrun": "2026-08-20 11:00:00"}}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {"lastrun": "2026-08-20 10:00:00"},
                                            "tok-2": {"lastrun": "2026-08-20 11:00:00"}}


def test_a_multi_valued_tag_takes_the_latest_value():
    """saveProjectTag APPENDS rather than replaces (verified live 2026-08-21: two runs left two
    values under azure-wi-lastrun). Multi-value is therefore the steady state, and the newest
    value is the real watermark -- taking the earliest would pin the window to the first run
    ever and re-scan all of history forever. Blanks are ignored, not treated as a value."""
    rows = [{"token": "tok-1", "tags": {"azure-wi-lastrun": ["2026-08-21 14:36:34", "",
                                                             "2026-08-21 14:55:01"]}}]
    assert syncstate.parse_tag_map(rows) == {"tok-1": {"lastrun": "2026-08-21 14:55:01"}}


def test_every_value_is_retained_for_pruning_even_though_one_wins():
    rows = [{"token": "tok-1", "tags": {
        "azure-wi-lastrun": ["2026-08-21 14:36:34", "2026-08-21 14:55:01"],
        "azure-wi-revsync": ["2026-08-21 14:56:00"]}}]
    assert syncstate.parse_tag_values(rows) == {"tok-1": {
        "lastrun": ["2026-08-21 14:36:34", "2026-08-21 14:55:01"],
        "revsync": ["2026-08-21 14:56:00"]}}


def test_superseded_never_includes_the_value_in_use():
    """A caller that saves the new watermark first and prunes second must not be handed the
    value it just wrote, or it would delete its own advance."""
    values = ["2026-08-21 14:36:34", "2026-08-21 14:55:01"]
    assert syncstate.superseded(values, "2026-08-21 14:55:01") == ["2026-08-21 14:36:34"]
    assert syncstate.superseded(values, "2026-08-21 14:36:34") == ["2026-08-21 14:55:01"]
    assert syncstate.superseded(["only"], "only") == []
    assert syncstate.superseded([], "x") == []
    assert syncstate.superseded(None, "x") == []


def test_malformed_list_values_are_skipped_not_fatal():
    rows = [{"token": "tok-1", "tags": {"azure-wi-lastrun": []}},
            {"token": "tok-2", "tags": {"azure-wi-lastrun": [12345]}},
            {"token": "tok-3", "tags": {"azure-wi-lastrun": ["   "]}},
            {"token": "tok-4", "tags": {"azure-wi-lastrun": [None, "2026-08-20 10:00:00"]}}]
    assert syncstate.parse_tag_map(rows) == {"tok-4": {"lastrun": "2026-08-20 10:00:00"}}


# --- the shape guard's discriminator ---
# "No project carries an azure-wi-* tag yet" is the normal first run, not a shape problem:
# 25 of the 28 rows in the live org carry only CLI scan tags (CTX, commitId, repoFullName).
# What proves the shape is a row the parser can structurally read — a string token and a
# tags container — not the presence of one of our keys in it.

def test_structurally_valid_rows_are_counted_even_when_none_carry_our_tags():
    rows = [{"name": "p", "token": "tok-1", "tags": {"CTX": ["abc"], "commitId": ["def"]}},
            {"name": "q", "token": "tok-2", "tags": {}}]
    assert syncstate.parse_tag_map(rows) == {}
    assert syncstate.count_parseable_rows(rows) == 2


def test_rows_in_the_wrong_shape_count_as_unparseable():
    rows = [{"projectToken": "tok-1", "tags": [{"key": "azure-wi-lastrun"}]},
            "not-a-dict",
            {"token": "", "tags": {}},
            {"token": "tok-2", "tags": "not-a-container"}]
    assert syncstate.count_parseable_rows(rows) == 0


def test_count_parseable_rows_tolerates_empty_input():
    assert syncstate.count_parseable_rows([]) == 0
    assert syncstate.count_parseable_rows(None) == 0
