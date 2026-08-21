from argparse import Namespace
import os
import sys

from mend_azure_wi_sync import core as _core

# Both import styles are supported by this codebase (see CLAUDE.md "Import quirk"): production
# runs core.py flatly (`from core import ...`), while this test package imports it via the
# package path (`from mend_azure_wi_sync import core`). Python treats those as two independent
# modules with independent globals unless the names are aliased to the same module object, so
# without this, a test that exercises the flat import path (e.g.
# test_run_sync_guard.py::test_the_flag_is_visible_through_the_flat_import_path) would import a
# freshly-executed second copy of core.py and never observe state set on the package-imported
# module. In the real process there is only ever one "core" module — this alias makes the test
# environment match that reality instead of accidentally exercising a split-brain artifact of
# running both import styles side by side.
sys.modules.setdefault("core", _core)


def pytest_addoption(parser):
    parser.addoption("--wsurl", action="store", default=os.environ.get("WS_APIKEY",'https://saas.whitesourcesoftware.com'))
    parser.addoption("--apikey", action="store", default=os.environ.get("WS_APIKEY"))
    parser.addoption("--wsuserkey", action="store", default=os.environ.get("WS_USERKEY"))
    parser.addoption("--utcdelta", action="store", default='0')
    parser.addoption("--azuretype", action="store", default='Task')
    parser.addoption("--azureuri", action="store", default=os.environ.get("WS_AZUREURI",'https://dev.azure.com/ps-mend/'))
    parser.addoption("--azurepat", action="store", default=os.environ.get("WS_AZUREPAT",'azurepat'))
    parser.addoption("--azurearea", action="store", default='')
    parser.addoption("--reset", action="store", default="False")
    parser.addoption("--azureproject", action="store", default=os.environ.get("WS_AZUREPROJECT",'AzureTestProject'))
    parser.addoption("--wsprojecttoken", action="store", default=os.environ.get("WS_PROJECTTOKEN"))
    parser.addoption("--wsproducttoken", action="store", default=os.environ.get("WS_PRODUCTTOKEN"))


def pytest_configure(config):
    global args
    args = Namespace(ws_org_token=config.getoption("apikey"), ws_user_key=config.getoption("wsuserkey"),
                     reset=config.getoption("reset"),
                     ws_prj=config.getoption("wsprojecttoken"),utc_delta=config.getoption("utcdelta"),
                     ws_prd=config.getoption("wsproducttoken"),ws_url=config.getoption("wsurl"),
                     azure_uri=config.getoption("azureuri"),azure_pat=config.getoption("azurepat"),
                     azure_prj=config.getoption("azureproject"),azure_area=config.getoption("azurearea"),
                     azure_type=config.getoption("azuretype"))
    return args


import pytest


@pytest.fixture(autouse=True)
def reset_core_globals():
    """core.py holds mutable module globals that leak between tests."""
    from mend_azure_wi_sync import core
    saved = (core.exist_wis, core.updated_wi, core.global_errors, core.conf, core.mend_v2_session,
             core.run_failed, core.synced_projects, core.entities_rows, core.enrichment_disabled,
             core.project_uuid_map, core.resolved_project_names, core.project_tag_state,
             core.project_tag_values, core.tag_state_available, core.TAG_WARNED)
    core.exist_wis = []
    core.updated_wi = []
    core.global_errors = 0
    core.mend_v2_session = None
    core.run_failed = False
    core.synced_projects = []
    core.entities_rows = None
    core.enrichment_disabled = False
    core.project_uuid_map = {}
    core.resolved_project_names = None
    core.project_tag_state = None
    core.project_tag_values = {}
    core.tag_state_available = True
    core.TAG_WARNED = False
    yield
    (core.exist_wis, core.updated_wi, core.global_errors, core.conf, core.mend_v2_session,
     core.run_failed, core.synced_projects, core.entities_rows, core.enrichment_disabled,
     core.project_uuid_map, core.resolved_project_names, core.project_tag_state,
     core.project_tag_values, core.tag_state_available, core.TAG_WARNED) = saved
