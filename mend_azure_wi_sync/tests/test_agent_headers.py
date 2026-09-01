"""Every Mend call identifies the tool through agent-name / agent-version request headers.

Mend's API logs these two headers, and they are the only thing that distinguishes this
integration from any other Python client in that log. Without them requests arrive under
requests' default python-requests/x.y User-Agent and cannot be attributed to the tool at all.

The values come from AGENT_INFO, which derives from __tool_name__ and __version__, so the
headers track the shipped name and the CI date-derived version with nothing to hand-maintain.
The ps- prefix is the shared naming convention across the Professional Services integrations,
and the replace() runs over the whole string so the prefix itself is unaffected.

2.0 and 3.0 have no request-side agent field of their own, so the identification travels as
headers on every call, the login included.
"""

from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync._version import __version__

AGENT = "ps-azure-wi-sync"


def _conf():
    return mock.MagicMock(email="a@b.c", ws_user_key="uk", org_uuid="org-1", proxy={},
                          ssl_verify=True, azure_project="TestProj", azure_pat="pat",
                          azure_uri="https://dev.azure.com/org")


def test_the_agent_name_carries_the_ps_prefix_and_the_hyphenated_tool_name():
    assert core.AGENT_INFO["agent"] == AGENT


def test_the_agent_version_is_the_shipped_version():
    assert core.AGENT_INFO["agentVersion"] == __version__


def test_the_2_0_login_identifies_the_tool():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_api_url", return_value="https://api-saas.mend.io"), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(status_code=200, text="{}")
        core._post_v2_login()
    headers = post.call_args.kwargs["headers"]
    assert headers["agent-name"] == AGENT
    assert headers["agent-version"] == __version__


def test_the_get_transport_identifies_the_tool():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok", {})
    headers = get.call_args.kwargs["headers"]
    assert headers["agent-name"] == AGENT
    assert headers["agent-version"] == __version__


def test_the_batch_paths_get_identifies_the_tool():
    """The timeout branch is a separate requests.get call and was easy to miss."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v2.0/x", "tok", {}, timeout=5)
    headers = get.call_args.kwargs["headers"]
    assert headers["agent-name"] == AGENT
    assert headers["agent-version"] == __version__


def test_the_3_0_post_transport_identifies_the_tool():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "post") as post:
        post.return_value = mock.MagicMock(status_code=200, text="{}")
        core._post_v3("https://api-saas.mend.io/api/v3.0/x", "tok", {}, {})
    headers = post.call_args.kwargs["headers"]
    assert headers["agent-name"] == AGENT
    assert headers["agent-version"] == __version__


def test_identification_does_not_displace_the_existing_headers():
    """Authorization is what makes the call work at all; the identification is additive."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "get") as get:
        get.return_value = mock.MagicMock(status_code=200, text="{}")
        core._get_v2("https://api-saas.mend.io/api/v3.0/x", "tok-9", {})
    headers = get.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer tok-9"
    assert headers["Content-Type"] == "application/json"


def test_azure_devops_is_not_sent_the_mend_identification():
    """These headers mean something to Mend's logs and nothing to Azure DevOps."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core.requests, "request") as req:
        req.return_value = mock.MagicMock(status_code=200, text="{}")
        core.call_azure_api(api_type="GET", api="wit/workitems/1", data={}, project="TestProj")
    assert "agent-name" not in req.call_args.kwargs["headers"]
