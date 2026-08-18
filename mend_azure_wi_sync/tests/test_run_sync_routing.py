from unittest import mock

from mend_azure_wi_sync import core


def _conf(routing="true", exclude="", product="", project=""):
    return mock.MagicMock(routing=routing, branches="main,master", azure_project="Bookkeeping",
                          reponame="", wsproducttoken=product, wsprojecttoken=project,
                          wsexcludetoken=exclude)


TAGS = {
    "tok-a": [{"key": "azure-project", "value": "Platform"},
              {"key": "azure-repo", "value": "api"},
              {"key": "azure-branch", "value": "refs/heads/main"}],
    "tok-b": [{"key": "azure-project", "value": "Tools"},
              {"key": "azure-repo", "value": "cli"},
              {"key": "azure-branch", "value": "refs/heads/main"}],
    "tok-c": [],
}


def _patches(conf, known={"Platform", "Tools"}):
    """Start the common patches; every test using this must call mock.patch.stopall()."""
    for p in (mock.patch.object(core, "conf", conf),
              mock.patch.object(core, "get_prj_list_modified", return_value=list(TAGS)),
              mock.patch.object(core, "fetch_project_tags", return_value=TAGS),
              mock.patch.object(core, "list_azure_projects", return_value=known),
              mock.patch.object(core, "set_lastrun", return_value=0)):  # not called here; guards regressions
        p.start()


def test_routing_off_does_not_call_the_tag_api():
    with mock.patch.object(core, "conf", _conf(routing="false")), \
         mock.patch.object(core, "get_prj_list_modified", return_value=["tok-a"]), \
         mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value="done"), \
         mock.patch.object(core, "fetch_project_tags") as tags:
        core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
    tags.assert_not_called()


def test_routing_on_syncs_each_azure_target_once():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]) as exist, \
         mock.patch.object(core, "create_wi", return_value="done"):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert exist.call_count == 2          # once per Azure project, not once per Mend project
    assert "2 of 3" in result


def test_excluded_token_is_never_synced_and_is_reported_distinctly():
    conf = _conf(exclude="tok-b")
    created = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi",
                           side_effect=lambda t, *a, **k: created.append(t) or "done"):
        _patches(conf)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()

    assert "tok-b" not in created
    assert "scope-excluded" in result


def test_untagged_project_is_never_synced():
    conf = _conf()
    created = []
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi",
                           side_effect=lambda t, *a, **k: created.append(t) or "done"):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert "tok-c" not in created


def test_aborts_when_the_project_list_cannot_be_read():
    conf = _conf()
    with mock.patch.object(core, "create_wi") as create:
        _patches(conf, known=None)
        try:
            result = core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    create.assert_not_called()
    assert "aborted" in result.lower()


def test_a_failed_target_does_not_stop_the_others():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", side_effect=[None, []]), \
         mock.patch.object(core, "create_wi", return_value="done") as create:
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert create.call_count == 1


def test_conf_azure_project_is_restored():
    conf = _conf()
    with mock.patch.object(core, "get_exist_wi", return_value=[]), \
         mock.patch.object(core, "create_wi", return_value="done"):
        _patches(conf)
        try:
            core.run_sync(st_date="", end_date="", custom_flds=[], wi_type="Task")
        finally:
            mock.patch.stopall()
    assert conf.azure_project == "Bookkeeping"


def test_expand_product_tokens_survives_a_non_json_response():
    """The original raised JSONDecodeError here and killed the whole run."""
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="k", ws_org_token="o")), \
         mock.patch.object(core, "call_ws_api", return_value=""):
        assert core.expand_product_tokens("prd-1") is None   # None, not [] — see the scope guard
