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
    wsuserkey = ("MEND_USERKEY",)
    wsurl = ("MEND_WSS_URL", "MEND_URL")
    wsproduct = ("MEND_PRODUCTTOKEN",)
    wsproject = ("MEND_PROJECTTOKEN",)
    wsazureuri = ("MEND_AZUREURI",)
    wsazurepat = ("MEND_AZUREPAT",)
    wsazureproject = ("MEND_AZUREPROJECT",)
    wsexcludetoken = ("MEND_EXCLUDETOKEN",)
    wsazurearea = ("MEND_AZUREAREA",)
    wsazuretype = ("MEND_AZURETYPE",)
    wscustomfields = ("MEND_CUSTOMFIELDS",)
    wsdependency = ("MEND_DEPENDENCY",)
    wsreponame = ("MEND_REPONAME",)
    azuredesc = ("MEND_DESCRIPTION",)
    azurepriority = ("MEND_CALCULATEPRIORITY",)
    proxy = ("PROXY", "MEND_PROXY")
    wsrouting = ("MEND_ROUTING",)
    wsbranches = ("MEND_BRANCHES",)
    wsreachability = ("MEND_REACHABILITY",)
    wsemail = ("MEND_EMAIL",)
    wsorguuid = ("MEND_ORGUUID",)
    wsseverity = ("MEND_SEVERITY",)
    wsclosedstate = ("MEND_CLOSEDSTATE",)
    wsreopenstate = ("MEND_REOPENSTATE",)
    wssslverify = ("MEND_SSLVERIFY",)
    wsdeppaths = ("MEND_DEPPATHS",)
    wsdeppathsconcurrency = ("MEND_DEPPATHS_CONCURRENCY",)

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
    ws_url: str
    azure_uri: str
    azure_project: str
    azure_pat: str
    utc_delta: int
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
    proxy: str
    routing: str
    branches: str
    reachability: str
    email: str
    org_uuid: str
    severity: str
    closed_state: str
    reopen_state: str
    # Defaulted, unlike every field above it: "" means verify (see core.verify_setting), so an
    # existing Config(...) call that predates this variable keeps working AND gets the secure
    # behaviour rather than having to opt in.
    ssl_verify: str = ""
    # Defaulted like ssl_verify above: the accessor (core.dep_paths_enabled /
    # core.library_paths_pool_size) owns the actual default, not update_properties, so an
    # existing Config(...) call that predates these two variables keeps working unchanged.
    dep_paths: str = ""
    dep_paths_concurrency: str = ""

    def conf_json(self):
        return {
            "wsuserkey": self.ws_user_key,
            "wsurl": self.ws_url,
            "wsazureuri": self.azure_uri,
            "wsazureproject": self.azure_project,
            "wsazurepat": self.azure_pat,
            "wsazurearea": self.azure_area,
            "utcdelta": self.utc_delta,
            "wsproducttoken": self.wsproducttoken,
            "wsprojecttoken": self.wsprojecttoken,
            "wsexcludetoken": self.wsexcludetoken,
            "wsazuretype": self.azure_type,
            "wscustomfields": self.azure_custom,
            "wsdependency" : self.dependency,
            "wsreponame" : self.reponame,
            "azuredesc" : self.description,
            "azurepriority" : self.priority,
            "proxy" : self.proxy,
            "wsrouting": self.routing,
            "wsbranches": self.branches,
            "wsreachability": self.reachability,
            "wsemail": self.email,
            "wsorguuid": self.org_uuid,
            "wsseverity": self.severity,
            "wsclosedstate": self.closed_state,
            "wsreopenstate": self.reopen_state,
            "wssslverify": self.ssl_verify,
            "wsdeppaths": self.dep_paths,
            "wsdeppathsconcurrency": self.dep_paths_concurrency,
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
                elif key == "reachability":
                    value = "false" if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
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