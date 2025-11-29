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
    ReproSteps = ("Bug")

    @classmethod
    def get_name_by_value(cls, value):
        for member in cls:
            if value in member.value:
                return member.name
        return ""


class SeverityMapping(Enum):
    """Maps CVSS 3 scores to Azure Work Item severity levels"""
    CRITICAL = ("1 - Critical", 9.0, 10.0)
    HIGH = ("2 - High", 7.0, 8.9)
    MEDIUM = ("3 - Medium", 4.0, 6.9)
    LOW = ("4 - Low", 0.1, 3.9)
    NONE = ("", 0.0, 0.0)

    @classmethod
    def get_severity_by_cvss_score(cls, cvss_score: float):
        """Map CVSS 3 score to Azure severity level"""
        try:
            score_value = float(cvss_score)
            for member in cls:
                min_score = member.value[1]
                max_score = member.value[2]
                if min_score <= score_value <= max_score:
                    return member.value[0]
        except (ValueError, TypeError):
            pass
        return cls.NONE.value[0]


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
    azureseverity = ("WS_CALCULATESEVERITY", "MEND_CALCULATESEVERITY")
    wsalert = ("WS_ALERT", "MEND_ALERT")
    proxy = ("PROXY", "MEND_PROXY")

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
    severity: str
    wsalert: str
    proxy: str

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
            "azureseverity" : self.severity,
            "wsalert" : self.wsalert,
            "proxy" : self.proxy
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
                    value = self.azure_project if not properties[key] else properties[key]
                elif key == "description":
                    value = DescAzure.get_name_by_value(self.azure_type) if re.match(r"\$\(.+\)$", properties[key]) or not properties[key] else properties[key]
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