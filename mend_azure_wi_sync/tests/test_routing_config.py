import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs


def test_routing_defaults_to_empty_when_unset():
    with mock.patch.dict(os.environ, {}, clear=True):
        assert varenvs.get_env("wsrouting") == ""


def test_routing_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_ROUTING": "true"}, clear=True):
        assert varenvs.get_env("wsrouting") == "true"
    with mock.patch.dict(os.environ, {"WS_ROUTING": "true"}, clear=True):
        assert varenvs.get_env("wsrouting") == "true"


def test_branches_reads_mend_alias():
    with mock.patch.dict(os.environ, {"MEND_BRANCHES": "main,release/*"}, clear=True):
        assert varenvs.get_env("wsbranches") == "main,release/*"


VALID = "a" * 64          # satisfies token_pattern in check_patterns


def _valid_conf(**overrides):
    """A real Config with every field check_patterns reads set to a valid value.

    check_patterns dereferences conf.ws_user_key through re.match on its FIRST line
    (core.py:69), so a bare MagicMock raises TypeError before any assertion can run.
    """
    from mend_azure_wi_sync.config import Config
    fields = dict(ws_user_key=VALID, ws_org_token=VALID, ws_url="https://saas.mend.io",
                  azure_uri="https://dev.azure.com/org/", azure_project="Platform",
                  azure_pat=VALID, utc_delta=0, reset="false", wsproducttoken="",
                  wsprojecttoken="", wsexcludetoken="", azure_area="", azure_type="Task",
                  azure_custom="", dependency="true", reponame="", description="ReproSteps",
                  priority="false", wsalert="true", proxy="", routing="false",
                  branches="main,master", epss="false", reachability="false", maxlookback="720",
                  email="", api_url="", org_uuid="")
    fields.update(overrides)
    return Config(**fields)

def test_check_patterns_rejects_a_mistyped_routing_value():
    """A typo must fail loudly. Falling through to token selection with empty tokens
    would sync ~400 Mend projects into one Azure project with no error at all."""
    with mock.patch.object(core, "conf", _valid_conf(routing="yes")):
        assert any("ROUTING" in el for el in core.check_patterns())


def test_check_patterns_accepts_valid_routing_values():
    for value in ("true", "false", "TRUE", "False"):
        with mock.patch.object(core, "conf", _valid_conf(routing=value)):
            assert not any("ROUTING" in el for el in core.check_patterns())


def test_check_patterns_rejects_an_empty_branch_list():
    """MEND_BRANCHES=mian or an unquoted YAML value sends every project to the QUIET
    branch-filtered bucket. Validate the setting rather than relying on the report."""
    with mock.patch.object(core, "conf", _valid_conf(routing="true", branches="")):
        assert any("BRANCHES" in el for el in core.check_patterns())


def test_check_patterns_rejects_a_slash_in_azure_project():
    """Azure reads 'MyProject/MyTeam' as {project}/{team} and returns HTTP 500. This is
    almost always a $(System.TeamProject)-style value that picked up a team suffix."""
    with mock.patch.object(core, "conf", _valid_conf(azure_project="Platform/MyTeam")):
        assert any("AZUREPROJECT" in el for el in core.check_patterns())


def test_check_patterns_accepts_an_azure_project_without_a_slash():
    with mock.patch.object(core, "conf", _valid_conf(azure_project="Platform")):
        assert not any("AZUREPROJECT" in el for el in core.check_patterns())


def test_routing_no_longer_requires_mend_email():
    """MEND_EMAIL existed for the 2.0 login behind routing's /entities sweep. Routing tags
    come from the 1.4 org tag sweep now, so requiring an email would block a valid config for
    a login the tool never performs."""
    with mock.patch.object(core, "conf", _valid_conf(routing="true", branches="main")):
        assert not [el for el in core.check_patterns() if "MEND_EMAIL" in el]
