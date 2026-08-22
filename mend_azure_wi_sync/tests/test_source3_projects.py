from mend_azure_wi_sync import source3


def _row(uuid="p-1", name="api", app="a-1", tags=None):
    return {"uuid": uuid, "name": name, "path": "org/api",
            "applicationName": "ProductX", "applicationUuid": app,
            "creationDate": "2026-01-01", "lastScanned": "2026-08-20T10:00:00Z",
            "tags": tags if tags is not None else [],
            "labels": [], "statistics": {}}


def test_a_row_normalises_to_the_expected_shape():
    [p] = source3.normalise_projects([_row()])
    assert p["uuid"] == "p-1"
    assert p["name"] == "api"
    assert p["application_uuid"] == "a-1"
    assert p["application_name"] == "ProductX"
    assert p["last_scanned"] == "2026-08-20T10:00:00Z"


def test_tags_become_a_key_to_values_map():
    """routing.py consumes {key: [values]} -- the same shape the 1.4 tag sweep produced."""
    [p] = source3.normalise_projects([_row(tags=[
        {"name": "azure-project", "value": "Platform"},
        {"name": "azure-repo", "value": "api-service"},
    ])])
    assert p["tags"] == {"azure-project": ["Platform"], "azure-repo": ["api-service"]}


def test_a_repeated_tag_key_keeps_every_value():
    """A multi-valued routing tag is a real condition routing.py must see and rule on --
    collapsing it here would hide the ambiguity."""
    [p] = source3.normalise_projects([_row(tags=[
        {"name": "azure-project", "value": "A"},
        {"name": "azure-project", "value": "B"},
    ])])
    assert p["tags"]["azure-project"] == ["A", "B"]


def test_a_row_with_no_uuid_is_skipped():
    broken = _row()
    del broken["uuid"]
    assert source3.normalise_projects([broken, _row()]) == source3.normalise_projects([_row()])


def test_garbage_rows_return_empty_rather_than_raising():
    assert source3.normalise_projects(None) == []
    assert source3.normalise_projects(["nope"]) == []


def test_no_filters_selects_everything():
    projects = source3.normalise_projects([_row(uuid="p-1"), _row(uuid="p-2")])
    selected, unresolved = source3.select_projects(projects, [], [])
    assert {p["uuid"] for p in selected} == {"p-1", "p-2"}
    assert unresolved == []


def test_a_project_uuid_selects_only_it():
    projects = source3.normalise_projects([_row(uuid="p-1"), _row(uuid="p-2")])
    selected, _ = source3.select_projects(projects, ["p-2"], [])
    assert [p["uuid"] for p in selected] == ["p-2"]


def test_an_application_uuid_selects_all_its_projects():
    projects = source3.normalise_projects(
        [_row(uuid="p-1", app="a-1"), _row(uuid="p-2", app="a-1"), _row(uuid="p-3", app="a-2")])
    selected, _ = source3.select_projects(projects, ["a-1"], [])
    assert {p["uuid"] for p in selected} == {"p-1", "p-2"}


def test_excludes_are_subtracted_last():
    projects = source3.normalise_projects([_row(uuid="p-1", app="a-1"), _row(uuid="p-2", app="a-1")])
    selected, _ = source3.select_projects(projects, ["a-1"], ["p-2"])
    assert [p["uuid"] for p in selected] == ["p-1"]


def test_an_exclude_works_with_no_include():
    projects = source3.normalise_projects([_row(uuid="p-1"), _row(uuid="p-2")])
    selected, _ = source3.select_projects(projects, [], ["p-1"])
    assert [p["uuid"] for p in selected] == ["p-2"]


def test_an_unmatched_uuid_is_reported_not_silently_ignored():
    """Spec 4: the run must abort. Silently selecting nothing would read as 'no work to do'
    and, under reconciliation, close every work item in the project."""
    projects = source3.normalise_projects([_row(uuid="p-1")])
    selected, unresolved = source3.select_projects(projects, ["p-1", "typo-uuid"], [])
    assert unresolved == ["typo-uuid"]


def test_an_unmatched_exclude_is_also_reported():
    projects = source3.normalise_projects([_row(uuid="p-1")])
    _, unresolved = source3.select_projects(projects, [], ["typo-uuid"])
    assert unresolved == ["typo-uuid"]


def test_legacy_1_4_tokens_are_reported_as_unresolved():
    """The UUID-only clean break: an old MEND_PROJECTTOKEN value must fail loudly."""
    projects = source3.normalise_projects([_row(uuid="p-1")])
    _, unresolved = source3.select_projects(projects, ["abc123def456legacytoken"], [])
    assert unresolved == ["abc123def456legacytoken"]
