"""Real credentials against a real tenant. Excluded from a bare pytest run.

Run with: pytest -m live mend_azure_wi_sync/tests/test_entra_live.py -v
Requires MEND_AZURETENANTID, MEND_AZURECLIENTID, MEND_AZURECLIENTSECRET, MEND_AZUREURI
and MEND_AZUREPROJECT in the environment.

Anything beyond these two steps belongs in the live validation matrix in the spec, run by
a human against a real organization.
"""

import os

import pytest

from mend_azure_wi_sync import core

pytestmark = pytest.mark.live

REQUIRED = ("MEND_AZURETENANTID", "MEND_AZURECLIENTID", "MEND_AZURECLIENTSECRET",
            "MEND_AZUREURI", "MEND_AZUREPROJECT")


@pytest.fixture(autouse=True)
def _configured():
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        pytest.skip(f"live Entra credentials not set: {', '.join(missing)}")
    core.conf = core.startup()
    core.conf.update_properties()
    core.invalidate_azure_entra_token()


def test_a_real_token_is_minted():
    token = core.azure_entra_token()
    assert token, ("no token minted. Check the client secret Value (not the Secret ID), "
                   "both IDs, and that the runner can reach login.microsoftonline.com")
    assert token.count(".") == 2, "an Entra access token is a three-part JWT"


def test_the_token_can_read_work_items_from_the_configured_project():
    """Read-only. Proves organization membership, the Basic licence and Work Items read
    in one call, which is the whole of Part 2 of the customer setup guide."""
    payload, errorcode = core.call_azure_api(
        "POST", "wit/wiql", data={"query": "SELECT [System.Id] FROM WorkItems"},
        project=core.conf.azure_project, version="7.0",
        header="application/json")
    assert errorcode == 0, (
        f"WIQL read failed: {payload}. TF401444 means the service principal is not in "
        f"the organization; VS800075 means it is not in the project; a bare 401 means "
        f"permissions or a Stakeholder licence")
