from dataclasses import dataclass
import os
import sys
import re
from enum import Enum

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)


class DescAzure(Enum):
    Description = ("Epic", "Task", "Issue", "User Story", "Feature", "Test Plan", "Change Request",
                   "Test Suite", "Product Backlog Item", "Impediment", "Requirement", "Risk")
    ReproSteps = ("Bug",)

    @classmethod
    def get_name_by_value(cls, value):
        # Matched case-sensitively until 2026-08-19, and against a bare string for
        # ReproSteps — so `value in member.value` was a substring test. MEND_AZURETYPE=BUG
        # (which Azure DevOps itself accepts, being case-insensitive about type names)
        # resolved to "", and core.py's `if desc_field:` guard then dropped the description
        # patch entirely: work items were created with a title, tags and priority but no
        # description in any field, with nothing logged. Exact, case-insensitive match.
        for member in cls:
            values = member.value if isinstance(member.value, tuple) else (member.value,)
            if any(str(value).casefold() == str(known).casefold() for known in values):
                return member.name
        return ""


class varenvs(Enum):  # Lit of Env.variables
    wsuserkey = ("WS_USERKEY", "MEND_USERKEY")
    wsapikey = ("MEND_APIKEY","WS_APIKEY","WS_TOKEN")
    wsurl = ("WS_WSS_URL","MEND_WSS_URL","WS_URL","MEND_URL")
    wsproduct = ("WS_PRODUCTTOKEN", "MEND_PRODUCTTOKEN")
    wsproject = ("WS_PROJECTTOKEN", "MEND_PROJECTTOKEN")
    wsazureuri = ("WS_AZUREURI","MEND_AZUREURI")
    wsazurepat = ("WS_AZUREPAT","MEND_AZUREPAT")
    wsazureproject = ("WS_AZUREPROJECT","MEND_AZUREPROJECT")
    wsreset = ("WS_RESET","MEND_RESET")
    wsexcludetoken = ("WS_EXCLUDETOKEN","MEND_EXCLUDETOKEN")
    wsazurearea = ("WS_AZUREAREA","MEND_AZUREAREA")
    wsazuretype = ("WS_AZURETYPE","MEND_AZURETYPE")
    wscustomfields = ("WS_CUSTOMFIELDS","MEND_CUSTOMFIELDS")
    wsdependency = ("WS_DEPENDENCY","MEND_DEPENDENCY")
    wsreponame = ("WS_REPONAME","MEND_REPONAME")
    azuredesc = ("WS_DESCRIPTION","MEND_DESCRIPTION")
    azurepriority = ("WS_CALCULATEPRIORITY", "MEND_CALCULATEPRIORITY")
    wsalert = ("WS_ALERT", "MEND_ALERT")
    proxy = ("PROXY", "MEND_PROXY")
    wsrouting = ("WS_ROUTING", "MEND_ROUTING")
    wsbranches = ("WS_BRANCHES", "MEND_BRANCHES")
    wsepss = ("WS_EPSS", "MEND_EPSS")
    wsreachability = ("WS_REACHABILITY", "MEND_REACHABILITY")
    wsmaxlookback = ("WS_MAXLOOKBACK", "MEND_MAXLOOKBACK")
    wsemail = ("WS_EMAIL", "MEND_EMAIL")
    wsapiurl = ("WS_APIURL", "MEND_APIURL")
    wsorguuid = ("WS_ORGUUID", "MEND_ORGUUID")
    wsseverity = ("WS_SEVERITY", "MEND_SEVERITY")
    wsclosedstate = ("WS_CLOSEDSTATE", "MEND_CLOSEDSTATE")
    wsreopenstate = ("WS_REOPENSTATE", "MEND_REOPENSTATE")

    @classmethod
    def get_env(cls, key, alt_val=""):
        res = alt_val
        for el_ in cls.__dict__[key].value:
            res = os.environ.get(el_)
            if res:
                break
        res = "" if res is None else res
        return res


class Tags(Enum):
    license = ("LICENSE","license policy violation")
    vul_score = ("VULNERABILITY_SCORE","security vulnerability")
    vul_severity = ("VULNERABILITY_SEVERITY","security vulnerability")
    lib_age = ("LIBRARY_STALENESS","outdated library")
    regex = ("RESOURCE_NAME_REGEX","resource name template")
    gav_regex = ("GAV_REGEX","GAV data")
    product = ("PRODUCT", "exist in product")
    effect = ("EFFECTIVENESS","vulnerability effectiveness")

    @classmethod
    def get_el_by_name(cls, type: str):
        res = None
        for el_ in cls:
            if el_.value[0] == type:
                res = el_.value[1]
                break
        return res

    @classmethod
    def all_tags(cls) -> list:
        # Several policy match types map to the same tag string; de-duplicate while
        # preserving declaration order so the generated WIQL is stable.
        seen = []
        for el_ in cls:
            if el_.value[1] not in seen:
                seen.append(el_.value[1])
        return seen


@dataclass
class Config:
    ws_user_key: str
    ws_org_token: str
    ws_url: str
    azure_uri: str
    azure_project: str
    azure_pat: str
    utc_delta: int
    reset: str
    wsproducttoken: str
    wsprojecttoken: str
    wsexcludetoken: str
    azure_area: str
    azure_type: str
    azure_custom: str
    dependency: str
    reponame: str
    description: str
    priority: str
    wsalert: str
    proxy: str
    routing: str
    branches: str
    epss: str
    reachability: str
    maxlookback: str
    email: str
    api_url: str
    org_uuid: str
    severity: str
    closed_state: str
    reopen_state: str

    def conf_json(self):
        return {
            "wsuserkey": self.ws_user_key,
            "wsorgtoken": self.ws_org_token,
            "wsurl": self.ws_url,
            "wsazureuri": self.azure_uri,
            "wsazureproject": self.azure_project,
            "wsazurepat": self.azure_pat,
            "wsazurearea": self.azure_area,
            "utcdelta": self.utc_delta,
            "wsproducttoken": self.wsproducttoken,
            "wsprojecttoken": self.wsprojecttoken,
            "wsexcludetoken": self.wsexcludetoken,
            "wsreset": self.reset,
            "wsazuretype": self.azure_type,
            "wscustomfields": self.azure_custom,
            "wsdependency" : self.dependency,
            "wsreponame" : self.reponame,
            "azuredesc" : self.description,
            "azurepriority" : self.priority,
            "wsalert" : self.wsalert,
            "proxy" : self.proxy,
            "wsrouting": self.routing,
            "wsbranches": self.branches,
            "wsepss": self.epss,
            "wsreachability": self.reachability,
            "wsmaxlookback": self.maxlookback,
            "wsemail": self.email,
            "wsapiurl": self.api_url,
            "wsorguuid": self.org_uuid,
            "wsseverity": self.severity,
            "wsclosedstate": self.closed_state,
            "wsreopenstate": self.reopen_state,
        }

    def get_values(self):
        return vars(self)

    def update_properties(self):
        properties = vars(self)  # Get all properties of the Config object
        for key in properties:
            if key != "utc_delta":
                if key == "azure_type":
                    value = "Task" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "dependency":
                    value = "True" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "reponame":
                    # Under routing this is set per Mend project from the scan tag, and
                    # update_properties runs on every Azure call — backfilling it here would
                    # overwrite an intentionally empty value with the Azure project name.
                    value = properties[key] if (properties[key] or self.routing.lower() == "true") \
                        else self.azure_project
                elif key == "description":
                    value = DescAzure.get_name_by_value(self.azure_type) if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "routing":
                    value = "false" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "epss":
                    value = "false" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "reachability":
                    value = "false" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "maxlookback":
                    value = "720" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "branches":
                    value = "main,master" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "severity":
                    value = "high" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "closed_state":
                    value = "Closed" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "reopen_state":
                    value = "New" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
                elif key == "proxy":
                    if properties[key]:
                        if type(properties[key]) is dict:
                            value = properties[key]
                        elif type(properties[key]) is str:
                            if "https://" not in properties[key] and "http://" not in properties[key]:
                                value = {"http": f"http://{properties[key]}", "https": f"http://{properties[key]}"}
                            else:
                                value = {"http": properties[key], "https": properties[key]}
                        else:
                            value = {}
                    else:
                        value = {}
                else:
                    value = "" if re.match(r"\$\(.+\)$", properties[key]) else properties[key]
                setattr(self, key, value)