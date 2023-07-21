from argparse import Namespace
import os


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
