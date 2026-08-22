from unittest import mock

from mend_azure_wi_sync import core


def _conf_dependency():
    # Mirrors test_create_wi_verdict._conf_with_library(), with dependency mode on so both
    # library-level findings in this file land through the dependency-mode branch.
    return mock.MagicMock(azure_type="Task", dependency="true", wsalert="true",
                          epss="false", reachability="false", reponame="", routing="false",
                          ws_user_key="uk-123", description="", priority="false",
                          azure_area="", azure_project="TestProj")


def _lib_el(key_id, filename="shared-name.jar", cve="CVE-2024-0001"):
    """A minimally plausible policy-violation library element, shaped like
    test_create_wi_verdict._prj_el_with_one_cve() but parameterised on keyId/filename so two
    distinct libraries can be made to collide on title."""
    return {
        "library": {"url": "http://example.com/lib", "filename": filename,
                    "keyUuid": f"uuid-{key_id}", "keyId": key_id},
        "policy": {"name": "[X] Some Policy", "policyMatch": {"type": "VULNERABILITY_SCORE"}},
        "policyViolations": [
            {"violationType": "VULNERABILITY", "issueUuid": f"issue-{key_id}",
             "vulnerability": {"name": cve, "severity": "high",
                                "cvss3_score": 9.8, "score": 9.8, "description": "desc",
                                "url": "http://example.com/cve", "publishDate": "2024-01-01",
                                "topFix": {"url": "http://example.com/fix", "date": "2024-02-01",
                                           "type": "upgrade", "fixResolution": "upgrade to 2.0"}}}
        ],
    }


def test_same_title_collision_from_different_keyid_is_logged_not_silent():
    """FINDING 1: two distinct libraries that share a filename (e.g. same artifact name from
    two different groupIds -- a real Maven/npm case) render the same dependency-mode title.
    The second one resolves to the first's work item id and the pre-existing
    `exist_id not in updated_wi` guard already skips it -- before this fix that skip was
    completely silent. This drives the real create_wi with two such libraries in one Mend
    project and asserts a warning names both libraries and the shared work item id."""
    conf = _conf_dependency()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _lib_el(1), _lib_el(2)]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api", return_value=({"id": 42}, 0)), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "wi_claim_keyid", {}), \
         mock.patch.object(core, "logger") as logger:
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")

    warnings = [str(c.args[0]) for c in logger.warning.call_args_list]
    assert any("42" in w and "keyId=1" in w and "keyId=2" in w for w in warnings), warnings


def test_two_libraries_with_different_filenames_do_not_warn():
    """Sanity check: distinct titles must never trip the collision warning."""
    conf = _conf_dependency()
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _lib_el(1, filename="lib-a.jar"),
                                        _lib_el(2, filename="lib-b.jar")]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api", return_value=({"id": 42}, 0)), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "wi_claim_keyid", {}), \
         mock.patch.object(core, "logger") as logger:
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")

    assert logger.warning.call_count == 0


def test_replace_updates_exist_wis_cache_with_the_new_title():
    """FINDING 2: a PATCH (rename) must refresh the exist_wis cache entry, not just leave the
    stale title cached alongside the new one. Seeds exist_wis with a differently-counted-titled
    entry so check_wi_id_matching/matches_library matches it on library name and
    create_wi_content takes the PATCH/replace branch, then checks that the cache holds exactly
    one entry for that id, keyed by the NEW title."""
    conf = _conf_dependency()
    stale_title = "shared-name.jar: 3 vulnerabilities (highest severity is 5.0)"
    seeded_exist_wis = [{stale_title: {42: "Prod/Proj; security vulnerability"}}]
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_prj_policy",
                           return_value=["Prod", "Proj", _lib_el(1)]), \
         mock.patch.object(core, "call_ws_api",
                           return_value='{"libraries": [], "libraryLocations": []}'), \
         mock.patch.object(core, "call_azure_api",
                           return_value=({"id": 42, "fields": {"System.WorkItemType": "Task"}}, 0)), \
         mock.patch.object(core, "exist_wis", seeded_exist_wis), \
         mock.patch.object(core, "updated_wi", []), \
         mock.patch.object(core, "wi_claim_keyid", {}):
        core.create_wi("tok-1", "2026-08-01 00:00:00", "2026-08-20 12:00:00", [], "Task")

    # mock.patch.object restores core.exist_wis to whatever it pointed to before the `with`
    # block on exit, so the object to inspect is the one create_wi mutated in place --
    # `seeded_exist_wis` itself -- not `core.exist_wis` after the block has closed.
    ids_to_titles = {}
    for d in seeded_exist_wis:
        for title, entry in d.items():
            for wi_id in entry:
                ids_to_titles.setdefault(wi_id, []).append(title)

    assert ids_to_titles.get(42) == [
        "shared-name.jar: 1 vulnerabilities (highest severity is 9.8)"]
