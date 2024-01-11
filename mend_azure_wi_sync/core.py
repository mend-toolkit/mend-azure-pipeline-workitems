import datetime
import inspect
import json
import logging
import os
import subprocess

import requests
import sys

sys.path.append(os.path.dirname(__file__))
from _version import __tool_name__, __version__
from config import *
import warnings
from urllib3.exceptions import InsecureRequestWarning

log_fmt_debug = "[%(asctime)s] [%(levelname)s] [%(funcName)s:%(lineno)d] %(message)s"
log_fmt_info = "[%(asctime)s] [%(levelname)s] %(message)s"
log_level = logging.DEBUG if (os.environ.get("DEBUG", "false")).lower() == "true" else logging.INFO
log_fmt = log_fmt_debug if log_level == logging.DEBUG else log_fmt_info

logging.basicConfig(level=log_level,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format=log_fmt,
                    datefmt='%y-%m-%d %H:%M:%S')

logger = logging.getLogger(__tool_name__)
logging.getLogger('urllib3').setLevel(logging.WARNING)

logger_vsts = logging.getLogger('vsts')
logger_vsts.setLevel(logging.INFO)
logger_msrest = logging.getLogger('msrest')
logger_msrest.setLevel(logging.INFO)
reset_back_time = 87600  # 10 years in hours

conf = None
max_wi = 100
WARNING_MSG = False
API_VERSION = "1.4"
AGENT_INFO = {"agent": f"{__tool_name__.replace('_', '-')}", "agentVersion": __version__}
DEFAULT_PRIORITY = 2
uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
token_pattern = r"^[0-9a-zA-Z]{64}$"
azurearea = r"^[0-9a-zA-Z\s\-_]+$"
global_errors = 0
exist_wis = []
updated_wi = []


def fn():
    fn_stack = inspect.stack()[1]
    return f'{fn_stack.function}:{fn_stack.lineno}'


def ex():
    e_type, e_msg, tb = sys.exc_info()
    return f'{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}'


def try_or_error(supplier, msg):
    try:
        return supplier()
    except:
        return msg


def check_patterns():
    res = []
    if not (re.match(uuid_pattern, conf.ws_user_key) or re.match(token_pattern, conf.ws_user_key)):
        res.append("MEND_USERKEY")
    if not (re.match(uuid_pattern, conf.ws_org_token) or re.match(token_pattern, conf.ws_org_token)):
        res.append("MEND_APIKEY")
    if conf.wsproducttoken:
        prods = conf.wsproducttoken.split(",")
        for prod_ in prods:
            if not (re.match(uuid_pattern, prod_) or re.match(token_pattern, prod_)):
                res.append("MEND_PRODUCTTOKEN")
                break
    if conf.wsprojecttoken:
        projs = conf.wsprojecttoken.split(",")
        for proj_ in projs:
            if not (re.match(uuid_pattern, proj_) or re.match(token_pattern, proj_)):
                res.append("MEND_PROJECTTOKEN")
                break
    if conf.wsexcludetoken:
        excludes = conf.wsexcludetoken.split(",")
        for excl_ in excludes:
            if not (re.match(uuid_pattern, excl_) or re.match(token_pattern, excl_)):
                res.append("MEND_EXCLUDETOKEN")
                break
    if conf.azure_area:
        areas = conf.azure_area.split("\\")
        for area_ in areas:
            if not re.match(azurearea, area_):
                res.append("MEND_AZUREAREA")
                break
    if not conf.azure_project:
        res.append("MEND_AZUREPROJECT")
    if not conf.azure_pat:
        res.append("MEND_AZUREPAT")
    if not conf.ws_url:
        res.append("MEND_URL")
    if not conf.azure_uri:
        res.append("MEND_AZUREURI")
    if conf.azure_custom and "::" not in conf.azure_custom:
        res.append(f"MEND_CUSTOMFIELDS ('{conf.azure_custom}')")
    if conf.proxy:
        proxy_str = try_or_error(lambda: conf.proxy['http'], try_or_error(lambda: conf.proxy['https'],""))
        if proxy_str.count(":") < 2:
            res.append("MEND_PROXY.(The right format is <proxy_ip>:<proxy_port>)")
    return res


def get_lastrun(time_delta: int, reset: str):
    if reset.lower() == "true":
        last_run = (datetime.datetime.now() + datetime.timedelta(hours=time_delta) -
                    datetime.timedelta(hours=reset_back_time)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        azure_prj_id = get_azure_prj_id(conf.azure_project)
        if azure_prj_id:
            r, errorcode = call_azure_api(api_type="GET", api=f"projects/{azure_prj_id}/properties", data={},
                                          version="7.0-preview", cmd_type="?keys=Lastrun&", header="application/json")
        last_run = try_or_error(lambda: r["value"][0]["value"],
                                (datetime.datetime.now() + datetime.timedelta(hours=time_delta) -
                                 datetime.timedelta(hours=reset_back_time)).strftime("%Y-%m-%d %H:%M:%S"))
    return last_run


def set_lastrun(lastrun: str):
    global global_errors
    azure_prj_id = get_azure_prj_id(conf.azure_project)
    errorcode = 2
    if azure_prj_id:
        data = [{
            "op": "add",
            "path": "/Lastrun",
            "value": f"{lastrun}"
        }]

        r, errorcode = call_azure_api(api_type="PATCH", api="projects/{" + azure_prj_id + "}/properties", data=data,
                                      version="7.0-preview")
        if errorcode > 0:
            info_el = r.popitem()
            logger.error(f"[{fn()}] {info_el}")
            global_errors += 1
    else:
        logger.error(f"The Azure Project {conf.azure_project} was not found")
        global_errors += 1
    return errorcode


def get_azure_prj_id(prj_name: str):
    res = ""
    try:
        r, errorcode = call_azure_api(api_type="GET", api="projects", data={}, version="7.0", header="application/json")
        if errorcode == 0:
            for prj_ in r["value"]:
                if prj_["name"] == prj_name:
                    res = prj_["id"]
                    break
        elif errorcode == 2:  # Invalid Azure URI or PAT provided
            logger.error(f"[{fn()}] Invalid Azure URI or PAT was provided")
            exit(-1)
    except Exception as err:
        pass
    return res


def fetch_prj_policy(prj_token: str, sdate: str, edate: str):
    global conf
    if conf is None:
        conf = startup()
        conf.update_properties()
    try:
        data = json.dumps(
            {"requestType": "fetchProjectPolicyIssues",
             "userKey": conf.ws_user_key,
             "orgToken": conf.ws_org_token,
             "projectToken": prj_token,
             "policyActionType": "CREATE_ISSUE",
             "fromDateTime": sdate,
             "toDateTime": edate,
             })
        rt = json.loads(call_ws_api(data=data))
        rt_res = [rt['product']['productName'], rt['project']['projectName']]
        for rt_el_val in rt['issues']:
            if try_or_error(lambda: rt_el_val['policy']['enabled'], False):
                rt_res.append(rt_el_val)
    except Exception as err:
        rt_res = [f"[{ex()}] Process getting Policy issues failed: ", f"{err}"]

    return rt_res


def get_prj_list_modified(fromdate: str, todate: str):
    data = json.dumps(
        {"requestType": "getOrganizationLastModifiedProjects",
         "userKey": conf.ws_user_key,
         "orgToken": conf.ws_org_token,
         "fromDateTime": fromdate,
         "toDateTime": todate,
         "includeRequestToken": False
         })
    resp = call_ws_api(data=data, agent_info_login=True)
    if "Error" in resp:
        logger.error(f"[{fn()}] {resp}")
        exit(-1)
    else:
        response_ = json.loads(resp)
        try:
            err_msg = response_["errorMessage"]
            logger.error(f"[{fn()}] Getting modified projects failed: {err_msg}")
            exit(-1)
        except Exception as err:  # Getting list of modified projects
            res = response_["lastModifiedProjects"]
            return [r["apiToken"] for r in res]


def call_ws_api(data, header={"Content-Type": "application/json"}, method="POST", agent_info_login=False):
    global WARNING_MSG
    data_json = json.loads(data)
    data_json["agentInfo"] = AGENT_INFO
    if agent_info_login:
        data_json["agentInfo"]["agent"] = AGENT_INFO["agent"].replace("ps-", "ps-login-")
    try:
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always", InsecureRequestWarning)
            res_ = requests.request(
                method=method,
                url=f"{extract_url(conf.ws_url)}/api/v{API_VERSION}",
                data=json.dumps(data_json),
                headers=header,
                proxies=conf.proxy,
                verify=False
            )
        if not WARNING_MSG:
            for warning in warning_list:
                if issubclass(warning.category, InsecureRequestWarning):
                    index_of_see = str(warning.message).find("See:")
                    logger.warning(str(warning.message)[:index_of_see].strip())
                    WARNING_MSG = True

        res = res_.text if res_.status_code == 200 else ""
        if res:
            try:
                res_check = json.loads(res_.text)
            except:
                temp_http_proxy = try_or_error(lambda: conf.proxy["http"], "")
                if temp_http_proxy:
                    with warnings.catch_warnings(record=True) as warning_list:
                        warnings.simplefilter("always", InsecureRequestWarning)
                        res_ = requests.request(
                            method=method,
                            url=f"{extract_url(conf.ws_url)}/api/v{API_VERSION}",
                            data=json.dumps(data_json),
                            headers=header,
                            proxies={"http": temp_http_proxy},
                            verify=False
                        )
                    if not WARNING_MSG:
                        for warning in warning_list:
                            if issubclass(warning.category, InsecureRequestWarning):
                                index_of_see = str(warning.message).find("See:")
                                logger.warning(str(warning.message)[:index_of_see].strip())
                                WARNING_MSG = True

                    res = res_.text if res_.status_code == 200 else ""
                else:
                    logger.error("Shutting down SSL/TLS connection. "
                                 "Check that your proxy is appropriately configured and run again.")
                    exit(-1)

    except Exception as err:
        res = f"Error was raised. {try_or_error(lambda: err.args[0].reason.args[0], '')}"
        logger.error(f'[{ex()}] {err}')
    return res


def call_azure_api(api_type: str, api: str, data={}, version: str = "6.0", project: str = "", cmd_type: str = "?",
                   header: str = "application/json-patch+json"):

    global conf, WARNING_MSG
    errorcode = 0
    conf = startup() if not conf else conf
    conf.update_properties()
    try:
        url = f"{conf.azure_uri}_apis/{api}{cmd_type}api-version={version}" if not project else \
            f"{conf.azure_uri}{project}/_apis/{api}{cmd_type}api-version={version}"
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always", InsecureRequestWarning)
            res_ = requests.request(api_type, url, json=data,
                                    headers={'Content-Type': f'{header}'},
                                    proxies=conf.proxy,
                                    verify=False,
                                    auth=('', conf.azure_pat))
        if not WARNING_MSG:
            for warning in warning_list:
                if issubclass(warning.category, InsecureRequestWarning):
                    index_of_see = str(warning.message).find("See:")
                    logger.warning(str(warning.message)[:index_of_see].strip())
                    WARNING_MSG = True
        if res_.status_code == 200:
            try:
                res = json.loads(res_.text)
            except json.JSONDecodeError as e:
                temp_http_proxy = try_or_error(lambda: conf.proxy["http"], "")
                if temp_http_proxy:
                    with warnings.catch_warnings(record=True) as warning_list:
                        warnings.simplefilter("always", InsecureRequestWarning)
                        res_ = requests.request(api_type, url, json=data,
                                                headers={'Content-Type': f'{header}'},
                                                proxies={"http": temp_http_proxy},
                                                verify=False,
                                                auth=('', conf.azure_pat))
                    if not WARNING_MSG:
                        for warning in warning_list:
                            if issubclass(warning.category, InsecureRequestWarning):
                                index_of_see = str(warning.message).find("See:")
                                logger.warning(str(warning.message)[:index_of_see].strip())
                                WARNING_MSG = True
                    try:
                        res = json.loads(res_.text)
                    except:
                        logger.error("Impossible to get data. "
                                     "Check that your proxy is appropriately configured and run again.")
                        exit(-1)
                else:
                    logger.error("Shutting down SSL/TLS connection. "
                                 "Check that your proxy is appropriately configured and run again.")
                    exit(-1)
            try:
                msg = res['message']
                logger.error(f"[{fn()}] Error: {msg}")
                errorcode = 1
            except:
                pass
        elif res_.status_code == 204 or res_.status_code == 201:  # Successful request but with nobody in the response
            return "", 0
        else:
            errorcode = 2
            if res_.text:
                msg = try_or_error(lambda: re.search(r"<title>(.*?)</title>", res_.text), "")
                msg_text = f'Status code: {res_.status_code}'
                msg_text = f'{msg_text} - {msg.group(1)}' if msg else f'{msg_text} - {try_or_error(lambda: json.loads(res_.text)["message"], "")}'
                res = {f"[{fn()}] {msg_text}"}
            elif res_.status_code == 401:
                res = {f"[{fn()}]  Non-valid authentication credentials or PAT does not have enough permissions."
                       f"Check it according to READ.ME file."}
            else:
                res = {f"[{fn()}] Azure API call failed": "No message text was returned."}
    except Exception as err:
        errorcode = 2
        res = {f"[{ex()}] Azure API call failed": f"{err}"}

    return res, errorcode


def get_exist_wi():
    def retrieve_work_items(work_item_ids):
        work_items = []
        batch_size = 200  # This is maximum for running one bulk
        num_batches = (len(work_item_ids) // batch_size) + 1

        for batch_index in range(num_batches):
            start_index = batch_index * batch_size
            end_index = min(start_index + batch_size, len(work_item_ids))
            batch_ids = work_item_ids[start_index:end_index]

            payload = {
                "ids": batch_ids,
                "fields": ["System.Id", "System.Title", "System.Tags", "System.WorkItemType"],  #"System.WorkItemType",
            }
            response, err = call_azure_api(api_type="POST", api="wit/workitemsbatch", version="6.0",
                                           data=payload, project=conf.azure_project, header="application/json")
            if err == 0:
                work_items.extend([{x["fields"]["System.Title"]: {x["fields"]["System.Id"]: try_or_error(lambda: x["fields"]["System.Tags"],"")}} for x in response["value"]])
                                   #if x["fields"]["System.WorkItemType"].lower() == conf.azure_type.lower()])

        return work_items

    global conf
    if conf is None:
        conf = startup()
        conf.update_properties()
    try:
        data = {"query": f'select [System.Id] From WorkItems Where '
                         f'[System.TeamProject] = "{conf.azure_project}" And [System.State] <> "Removed" AND [System.State] <> "Deleted"'}
        r, errocode = call_azure_api(api_type="POST", api="wit/wiql", version="6.0", project=conf.azure_project,
                                     data=data, header="application/json")
        if errocode == 0:
            ids = [x["id"] for x in r["workItems"]]
            return retrieve_work_items(work_item_ids=ids)
        else:
            return []
    except Exception as err:
        return []


def check_wi_id(id: str, project_name: str):
    try:
        values = [d[id] for d in exist_wis if id in d and project_name in ''.join(d[id].values())]
        res = try_or_error(lambda: max(values, key=lambda x: list(x.keys())[0]), 0)
        if type(res) is dict:
            return list(res.keys())[0]
        else:
            return res
    except:
        return 0


def update_wi_in_thread():
    global conf, global_errors
    if conf is None:
        conf = startup()
        conf.update_properties()
    try:
        logger.info("Start to update Mend’s data")
        first_id = 0
        executed_wi = 0
        tag_lic = Tags.get_el_by_name("LICENSE")
        tag_vul = Tags.get_el_by_name("VULNERABILITY_SCORE")
        while True:
            data = {"query": f'select [System.Id] From WorkItems Where '
                             f'[System.ChangedDate] > "{get_lastrun(conf.utc_delta, conf.reset)}" And '
                             f'[System.TeamProject] = "{conf.azure_project}" And [System.Id] > {first_id} '
                             f'AND (([System.Tags] CONTAINS "{tag_lic}") or ([System.Tags] CONTAINS "{tag_vul}")) '
                             f'And [System.State] <> "Removed" AND [System.State] <> "Deleted" '
                             f'ORDER BY [System.Id]'}
            r, errocode = call_azure_api(api_type="POST", api="wit/wiql", version="7.0", project=conf.azure_project,
                                         data=data, header="application/json",
                                         cmd_type=f"?timePrecision=True&$top={max_wi}&")
            results_wi = r["workItems"] if errocode == 0 else []
            if not results_wi:
                break
            id_str = ""
            for pos_number, wi_ in enumerate(results_wi):
                id_str += str(wi_["id"]) + ","
            first_id = try_or_error(lambda: wi_["id"], 0)
            id_str = id_str[:-1] if results_wi else ""

            if id_str:
                wi, errcode = call_azure_api(api_type="GET", api=f"wit/workitems?ids={id_str}&$expand=Relations",
                                             data={}, project=conf.azure_project, cmd_type="&")
                if errcode == 0:
                    for wq_el in wi['value']:
                        issue_id = wq_el['id']
                        issue_wi_title = wq_el['fields']['System.Title']
                        if list(set(try_or_error(lambda: wq_el['fields']['System.Tags'], "").split(";")) &
                                {f"{tag_vul}", f"{tag_lic}"}) or \
                            list(set(try_or_error(lambda: wq_el['fields']['System.Tags'], "").split(";")) &
                                 {f" {tag_vul}", f" {tag_lic}"}):
                            # If we have completely another task in the same Azure Project then just pass it
                            # Now Vulnerability and License violation are produced only
                            try:
                                uuid = ""
                                prj_token = ""
                                for wq_el_rel_ in wq_el['relations']:
                                    if wq_el_rel_['rel'] == "Hyperlink":
                                        prj_token = try_or_error(lambda: wq_el_rel_['attributes']['comment'].split(",")[0], "")
                                        uuid = try_or_error(lambda: wq_el_rel_['attributes']['comment'].split(",")[1], "")

                                wq_el_url = wq_el['url'][0:wq_el['url'].find("apis")] + f"workitems/edit/{issue_id}"
                                ext_issues = [{"identifier": f"{issue_wi_title}",
                                               "url": wq_el_url,
                                               "status": wq_el['fields']['System.State'],
                                               "lastModified": wq_el['fields']['System.ChangedDate'],
                                               "created": wq_el['fields']['System.CreatedDate']
                                               }]
                                try:
                                    if uuid and prj_token:
                                        data = json.dumps(
                                            {"requestType": "updateExternalIntegrationIssues",
                                             "userKey": conf.ws_user_key,
                                             "orgToken": conf.ws_org_token,
                                             "projectToken": prj_token,
                                             "wsPolicyIssueItemUuid": uuid,
                                             "externalIssues": ext_issues
                                             })
                                        json.loads(call_ws_api(data=data))
                                        #logger.info(f"Work item #{issue_id} updated corresponded to Mend's data successfully.")
                                except Exception as err:
                                    logger.error(f"[{ex()}] Work item #{issue_id} update Mend's data failed: {err}")
                                    global_errors += 1
                                executed_wi += 1
                            except Exception as err:
                                pass
        return f"Updated {executed_wi} corresponded Mend's item(s)"
    except Exception as err:
        global_errors += 1
        return f"[{ex()}] Update Mend's data failed: {err}"


def create_wi(prj_token: str, sdate: str, edate: str, cstm_flds: list, wi_type: str):
    def dep_hierarchy(key_uuid):
        def get_dependencies(dependencies):
            res = []
            for dependency in dependencies:
                res.append(dependency['fileName'])
                if 'dependencies' in dependency:
                    nested_dependencies = dependency['dependencies']
                    get_dependencies(nested_dependencies)
            return res

        data = json.dumps({
            "requestType": "getProjectLibraryDependencies",
            "userKey": conf.ws_user_key,
            "projectToken": prj_token,
            "keyUuid": key_uuid
        })
        deps = json.loads(call_ws_api(data=data))
        try:
            errcode = deps["errorCode"]
            return []
        except:
            return get_dependencies(dependencies=try_or_error(lambda: deps["dependencies"][0],
                                                              try_or_error(lambda: deps["dependencies"], [])))

    def get_prj_licenses():
        data = json.dumps({
            "requestType": "getProjectLicenses",
            "userKey": conf.ws_user_key,
            "projectToken": prj_token
        })
        return json.loads(call_ws_api(data=data))

    def get_lib_locations():
        data = json.dumps({
            "requestType": "getProjectLibraryLocations",
            "userKey": conf.ws_user_key,
            "projectToken": prj_token
        })
        return json.loads(call_ws_api(data=data))

    def get_lib_lic(key_uuid):
        for lib_lic_ in prj_licenses['libraries']:
            if lib_lic_['keyUuid'] == key_uuid:
                lib_lic_licenses = try_or_error(lambda: lib_lic_['licenses'], [])
                lib_lic_data = []
                for lib_lic_licenses_ in lib_lic_licenses:
                    lib_lic_data.append((try_or_error(lambda: lib_lic_licenses_['references'][0]['reference'], ""),
                                         try_or_error(lambda: lib_lic_licenses_["name"], ""),
                                         try_or_error(lambda: lib_lic_licenses_["url"], "")))
                return try_or_error(lambda: lib_lic_['description'], ""), \
                       try_or_error(lambda: lib_lic_['references']['url'], ""), \
                       lib_lic_data, \
                       try_or_error(lambda: "Direct" if lib_lic_['directDependency'] else "Transitive", "Direct")
        return "", "", [("","","")], "Direct"

    def get_pathes(keyuuid_):
        for location_ in prj_lib_locations['libraryLocations']:
            if location_['keyUuid'] == keyuuid_:
                return try_or_error(lambda: location_['locations'][0]['dependencyFile'], ""), \
                       try_or_error(lambda: location_['locations'][0]['path'], "")
        return "", ""

    def set_priority(value: float):
        score = [70, 55, 40]  # Mend gradation of SCC scores
        z = value * 10
        i = 0
        for i, sc_ in enumerate(score):
            if z // sc_ == 1:
                break
        return i + 1

    def analyze_fields(fld: dict, prj: list):
        val = ""
        if fld["defaultValue"]:
            step1 = fld["defaultValue"].split("&")
            for st_ in step1:
                t = f"{mend_val(st_[5:], prj)}" if "MEND:" in st_ else st_
                if t:
                    if t.startswith("$"):
                        dict_env_val = conf.conf_json()
                        env_val = t[1:].strip()
                        for var_ in varenvs:
                            if env_val in var_.value:
                                var_name = var_.name
                                break
                        t = try_or_error(lambda: dict_env_val[var_name], "")
                    val += t
                elif "MEND:" in st_:
                    logger.warning(f"The field '{fld['referenceName']}' is empty. "
                                   f"Check the MEND_CUSTOMFIELDS syntax.")
        return fld["referenceName"], val.strip()

    def mend_val(alert_val: str, prj_el: list):
        temp = None
        for lst_ in alert_val.split("."):
            try:
                temp = try_or_error(lambda: temp[lst_], "No content") if temp is not None else prj_el[lst_]
                if type(temp) is list:
                    rs = ""
                    for el_ in temp:
                        if type(el_) is str:
                            rs += el_ + ","
                        elif type(el_) is dict:
                            temp = el_
                        elif type(el_) is list:
                            temp = temp[0]  # Take just first element
                            break
                    if rs:
                        return rs[:-1]
            except Exception as err:
                logger.error(f"[{ex()}] Custom field parsing failed: {err}")
                return ""
        return temp

    def field_name_in_data(fld_name: str):  # Don't need to add existing element to data
        res = False
        for el_ in data:
            if fld_name in el_["path"]:
                res = True
                break
        return res

    def create_area(area):
        areas = area.split("\\")
        if areas[0] != conf.azure_project:
            areas.insert(0, conf.azure_project)
            conf.azure_area = f"{conf.azure_project}\\{conf.azure_area}"
        res = {}
        for i, area_ in enumerate(areas):
            data = {
                'name': area_,
            }
            if i == 1:
                res, errcode = call_azure_api(api_type="POST", api=f"wit/classificationnodes/areas", data=data,
                                     project=conf.azure_project, header="application/json")
            elif 1 < i < len(areas):
                res, errcode = call_azure_api(api_type="POST", api=f"wit/classificationnodes/areas/{under}", data=data,
                                     project=conf.azure_project, header="application/json")
            under = f"{under}/{area_}" if i > 1 else area_
        return res

    def create_html_table(data):
        table_html = "<table style='border-collapse: collapse; table-layout: auto'>\n"  # Start of the table HTML with styles

        # Create the table header row
        table_html += "<tr>"
        for header in data[0].keys():
            if header != "URL":
                table_html += f"<th style='border: 1px solid black; padding: 5px;'><b>{header}</b></th>"
        table_html += "</tr>\n"

        # Create the table data rows
        for row in data:
            table_html += "<tr>"
            for j, value in enumerate(row.values()):
                if j == 0:
                    url_ = row["URL"]
                    table_html += f"<td style='border: 1px solid black; padding: 5px;'><a href='{url_}'>{value}</a></td>"
                elif j < len(row.values()) - 1:
                    table_html += f"<td style='border: 1px solid black; padding: 5px;'>{value}</td>"

            table_html += "</tr>\n"

        table_html += "</table>"  # End of the table HTML

        return table_html

    def find_parent_chain(key_uuid, libraries):
        # Helper function to recursively find the parent chain
        def find_parent_recursively(child_uuid, libraries, chain):
            for library in libraries:
                if 'dependencies' in library:
                    for dependency in library['dependencies']:
                        if dependency['keyUuid'] == child_uuid:
                            chain.append(library)
                            find_parent_recursively(library['keyUuid'], libraries, chain)
                            break

        parent_chain = []
        find_parent_recursively(key_uuid, libraries, parent_chain)
        return parent_chain

    def get_prj_lib_hierarchy():
        data = json.dumps({
            "requestType": "getProjectHierarchy",
            "userKey": conf.ws_user_key,
            "projectToken": prj_token
        })
        return json.loads(call_ws_api(data=data))

    def generate_expandable_section(summary, detail):
        html = f"<details>\n"
        html += f"  <summary>{summary}</summary>\n"
        html += f"  <p>{detail}</p>\n"
        html += f"</details>"
        return html

    def get_field_ref(fld_name):
        for c_fld_ in cstm_flds:
            if fld_name == c_fld_["name"]:
                return f"/fields/{c_fld_['referenceName']}"
        return f"/fields/Custom.{fld_name}"

    def create_wi_content(issue_id):
        global data, count_item, global_errors
        data = [
            {
                "op": azure_operation,
                "path": "/fields/System.Title",
                "value": vul_title
            },
            {
                "op": azure_operation,
                "path": "/fields/Microsoft.VSTS.Common.Priority",
                "value": priority
            },
            {
                "op": azure_operation,
                "path": "/fields/System.Tags",
                "value": ",".join(tags)
            },
        ]
        if conf.description == "Description":
            desc_field = "/fields/System.Description"
        elif conf.description == "ReproSteps":
            desc_field = "/fields/Microsoft.VSTS.TCM.ReproSteps"
        elif conf.description:
            desc_field = get_field_ref(conf.description)
        else:
            desc_field = ""
        if desc_field:
            data.append({
                "op": azure_operation,
                "path": desc_field,
                "value": desc
            })

        for custom_ in cstm_flds:
            fld_name, fld_val = analyze_fields(custom_, prj_el)
            if fld_val and not field_name_in_data(fld_name):
                data.append({
                    "op": "add",
                    "path": f"/fields/{fld_name}",
                    "value": fld_val
                })
            elif not fld_val and "Custom." in fld_name:
                data.append({
                    "op": "remove",
                    "path": f"/fields/{fld_name}",
                })


        if conf.azure_area:
            res = create_area(conf.azure_area)
            data.append(
                {
                    "op": azure_operation,
                    "path": "/fields/System.AreaPath",
                    "value": f"{conf.azure_area}"
                }
            )
        try:
            if azure_operation == "add":
                if issue_id:
                    data.append(
                        {
                            "op": "add",
                            "path": "/relations/-",
                            "value": {
                                "rel": "Hyperlink",
                                "url": lib_url,
                                "attributes": {"comment": prj_token + "," + issue_id}
                            }
                        }
                    )

                r, errcode = call_azure_api(api_type="POST", api=f"wit/workitems/${wi_type}", data=data,
                                            project=conf.azure_project)
                try:
                    exist_wis.append({lib_name: r["id"]})
                except Exception as err:
                    pass
                    #logger.warning(f"[{ex()}] Work item creation/update failed: {r}")

                status_op = "created"
            else:
                r, errcode = call_azure_api(api_type="PATCH", api=f"wit/workitems/{exist_id}", data=data,
                                            project=conf.azure_project)
                status_op = "updated"
            try:
                updated_wi.append(exist_id if exist_id > 0 else r["id"])
            except Exception as err:
                pass

            if errcode == 0:
                count_item += 1
                logger.info(f"{conf.azure_type} {r['id']} {status_op}")
            elif errcode == 1:
                logger.warning(f"{conf.azure_type} creation/update failed: {r['message']}")
            else:
                info_el = r.popitem()
                logger.error(f"[{fn()}] {info_el}")
        except Exception as err:
            logger.error(f"[{ex()}] Work item creation/update failed: {err}")
            global_errors += 1

    def generate_html_bulleted_list(items):
        html = "<ul>\n"
        for item in items:
            html += f"  <li>{item}</li>\n"
        html += "</ul>"
        return html

    def get_ingnored_alerts(project):
        ign_alerts = json.dumps({
            "requestType": "getProjectIgnoredAlerts",
            "userKey": conf.ws_user_key,
            "projectToken": project
        })
        res = []
        try:
            res_ = json.loads(call_ws_api(data=ign_alerts))["alerts"]
            res.extend([x["vulnerability"]["name"] for x in res_])
        except Exception as err:
            pass
        return res

    def is_ignored(cve, ignored):
        return cve in ignored

    global conf, global_errors, exist_wis, updated_wi, count_item
    try:
        ws_prj = fetch_prj_policy(prj_token, sdate, edate)
        ignore_alerts = get_ingnored_alerts(project=prj_token) if conf.wsalert.lower() == "false" else []
        prj_lib_hierarchy = try_or_error(lambda: get_prj_lib_hierarchy()["libraries"], [])
        prj_licenses = try_or_error(lambda: get_prj_licenses(), [])
        prj_lib_locations = try_or_error(lambda: get_lib_locations(), [])
        prd_name = ws_prj[0]
        prj_name = ws_prj[1]
        status_op = "created"
        count_item = 0
        sorted_libs = sorted(ws_prj[2:], key=lambda x: (x["library"]["keyId"], -len(x["policyViolations"])))
        for prj_el in sorted_libs:
            lib_url = prj_el["library"]["url"]
            lib_name = prj_el["library"]["filename"]
            policy_lic_name = try_or_error(
                lambda: prj_el['policy']['name'][prj_el['policy']['name'].find("]") + 1:].strip(), "")
            tags = [f"{prd_name}/{prj_name}", Tags.get_el_by_name(prj_el["policy"]["policyMatch"]["type"])]
            key_uuid = try_or_error(lambda: prj_el['library']['keyUuid'], "")
            path_dep, path_lib = get_pathes(key_uuid)
            list_dep_lib = dep_hierarchy(key_uuid=key_uuid)
            lib_desc, lib_home_page, lic_data_arr, lib_dep = get_lib_lic(key_uuid)
            is_license = prj_el["policy"]["policyMatch"]["type"] == "LICENSE"
            lib_hierarchy = find_parent_chain(key_uuid=key_uuid,
                                              libraries=prj_lib_hierarchy) if lib_dep == "Transitive" else []

            if conf.dependency.lower() == "true":  # Different process creation WI (related dependency or CVE)
                relevant_vuls = []
                max_severity = ""
                if not is_license:
                    for vuln_ in prj_el["policyViolations"]:
                        if not is_ignored(cve=vuln_["vulnerability"]["name"], ignored=ignore_alerts):
                            relevant_vuls.append(vuln_)
                    if relevant_vuls:
                        max_severity_el = max(relevant_vuls, key=lambda x:
                        float(try_or_error(lambda: x["vulnerability"]["cvss3_score"],
                                           try_or_error(lambda: x["vulnerability"]["score"], 0))))
                        max_severity = try_or_error(lambda: max_severity_el["vulnerability"]["cvss3_score"],
                                                    try_or_error(lambda: max_severity_el["vulnerability"]["score"], ""))
                vul_title = f"License Policy Violation detected in {lib_name}" if is_license else f"{lib_name}: " \
                                        f"{len(relevant_vuls)} vulnerabilities (highest severity is {max_severity})"
                hierarchy_libs = ""
                vulnerability_data = ""
                exist_id = check_wi_id(id=vul_title,project_name=f"{prd_name}/{prj_name}")
                # Looking for ID by System.Title and Tag (Product/Project Name)
                if exist_id > 0:
                    wi_data, err_ = call_azure_api(api_type="GET", api=f"wit/workitems/{exist_id}",
                                                   data={}, project=conf.azure_project)
                wi_type_ = try_or_error(lambda: wi_data["fields"]["System.WorkItemType"], "")
                if exist_id == 0:
                    azure_operation = "add"
                elif wi_type_.lower() != wi_type.lower():
                    call_azure_api(api_type="DELETE", api=f"wit//workitems/{exist_id}",
                                   data={}, project=conf.azure_project)
                    azure_operation = "add"
                else:
                    azure_operation = "replace"
                if exist_id not in updated_wi:
                    issue_id = try_or_error(lambda: prj_el["policyViolations"][0]["issueUuid"], "")
                    # For link take first IssuedID
                    if is_license:  # Different description creation for License and Vulnerability
                        lic_data = ""
                        for lic_data_ in lic_data_arr:
                            lic_data = lic_data + f"<a href='{lic_data_[2]}'>{lic_data_[1]}</a>" + \
                                       f"<br><b>License Reference File: </b><a href='{lic_data_[0]}'>{lic_data_[0]}</a><br>" \
                                       f"<b>License Policy Violation - </b>{policy_lic_name}<br>"
                        lic_data = generate_expandable_section("<b>License Details</b>",lic_data)
                        desc = "<b>Library - </b>" + lib_name + \
                               "<br>" + lib_desc + \
                               "<br><b>Path to dependency file: </b>" + path_dep + "<br><b>Path to library:</b>" + path_lib + \
                               "<br><b>Vulnerable Library: </b>" + lib_name + f"<br><b> Library home page: " \
                                                                              f"</b><a href='{lib_home_page}'>{lib_home_page}</a>" + lic_data
                    else:
                        table_data = []
                        for i, policy_el in enumerate(prj_el["policyViolations"]):
                            vul_name = f"License Policy Violation" if is_license else \
                                try_or_error(lambda: policy_el["vulnerability"]["name"], "")
                            if "License Policy Violation" in vul_name or not is_ignored(cve=vul_name, ignored=ignore_alerts):
                                vul_desc = try_or_error(lambda: policy_el["vulnerability"]["description"], "")
                                vul_origin_url = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["url"], "")
                                vul_publish_date = try_or_error(lambda: policy_el["vulnerability"]["publishDate"], "")
                                vul_fix_release_date = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["date"],
                                                                    "")
                                vul_severity = try_or_error(lambda: policy_el["vulnerability"]["cvss3_severity"],
                                                            try_or_error(lambda: policy_el["vulnerability"]["severity"],
                                                                         ""))
                                vul_score = try_or_error(lambda: policy_el["vulnerability"]["cvss3_score"],
                                                         try_or_error(lambda: policy_el["vulnerability"]["score"], ""))
                                vul_fix_resolution = try_or_error(lambda: policy_el["vulnerability"]["fixResolutionText"],
                                                                  "")
                                vul_fix_type = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["type"], "")
                                vul_url = lib_home_page if is_license else try_or_error(
                                    lambda: policy_el["vulnerability"]["url"], "")
                                table_data.append({
                                    "CVE": vul_name,
                                    "Severity": vul_severity,
                                    "CVSS": vul_score,
                                    "Dependency": lib_name,
                                    "Type": lib_dep,
                                    "Fixed in": vul_fix_resolution,
                                    "URL": vul_url
                                })
                                lic_data = "<br>"
                                for lic_data_ in lic_data_arr:
                                    lic_data = lic_data + f"<a href='{lic_data_[2]}'>{lic_data_[1]}</a>" + \
                                               f"<br><b>License Reference File: </b><a href='{lic_data_[0]}'>{lic_data_[0]}</a><br>" \
                                               f"<b>License Policy Violation - </b>{policy_lic_name}<br>"
                                lic_data = generate_expandable_section("<b>License Details</b>", lic_data) if is_license else ""

                                vul_data = "<b>Vulnerable Library:</b>" + lib_name + \
                                    "<br><b>Path to dependency file: </b>" + path_dep + "<br><b>Path to library:</b>" + path_lib + \
                                    "<br><b>Vulnerability Details:</b> " + vul_desc + "<br><b>Publish Date:</b> " + \
                                    vul_publish_date + \
                                    f"<br><b>URL:</b> <a href='{vul_url}'>{vul_name}</a>" + \
                                    "<br><b>CVSS 3 Score Details </b>(" + str(vul_score) + ")" \
                                                                                           "<br><b>Suggested Fix:</b> " + \
                                    vul_fix_type + f"<br><b>Origin:</b> <a href='{vul_origin_url}'></a><br>" \
                                                   f"<b>Release Date:</b> " + vul_fix_release_date + \
                                    "<br><b>Fix Resolution:</b> " + vul_fix_resolution
                                hierarchy_libs = generate_html_bulleted_list(items=[x["filename"] for x in lib_hierarchy] if lib_dep == "Transitive" else list_dep_lib)
                                vulnerability_data += generate_expandable_section(vul_name, vul_data + lic_data)

                        desc = create_html_table(data=table_data) if table_data else ""
                        desc_add = "<b>Library - </b>" + lib_name + \
                                   "<br>" + lib_desc + \
                                   "<br><b>Path to dependency file: </b>" + path_dep + "<br><b>Path to library:</b>" + path_lib + \
                                   "<br><b>Vulnerable Library: </b>" + lib_name + \
                                   "<br><b>Dependency Hierarchy: </b><br>" + hierarchy_libs + \
                                   f"<br><b> Library home page: " \
                                   f"</b><a href='{lib_home_page}'>{lib_home_page}</a>"
                        desc = generate_expandable_section(f"Vulnerable library - {lib_name}", desc_add) + "<br>" + \
                               desc + "<b>Details:</b><br>" if vulnerability_data else ""
                        desc += vulnerability_data

                    priority = set_priority(try_or_error(lambda: float(max_severity), 6)) if conf.priority.lower() == "true" else DEFAULT_PRIORITY
                    # Default priority is 2
                    if desc:  # Creation WI just in case existing data
                        create_wi_content(issue_id=issue_id)
            else:
                for i, policy_el in enumerate(prj_el["policyViolations"]):
                    if (is_license and policy_el["violationType"] == "LICENSE") or (
                            not is_license and policy_el["violationType"] == "VULNERABILITY"):
                        lic_num_vuln = f" #{str(i+1)}" if is_license and i>0 else ""
                        vul_name = f"License Policy Violation{lic_num_vuln}" if is_license else \
                            try_or_error(lambda: policy_el["vulnerability"]["name"], "")
                        if "License Policy Violation" in vul_name or not is_ignored(cve=vul_name, ignored=ignore_alerts):
                            issue_id = policy_el["issueUuid"]
                            vul_severity = try_or_error(lambda: policy_el["vulnerability"]["cvss3_severity"],
                                                        try_or_error(lambda: policy_el["vulnerability"]["severity"], ""))
                            if not vul_name:
                                break
                            vul_title = f"{vul_name} detected in {lib_name}" if is_license else \
                                f"{vul_name} ({str(vul_severity).capitalize()}) detected in {lib_name}"

                            vul_score = try_or_error(lambda: policy_el["vulnerability"]["cvss3_score"],
                                                     try_or_error(lambda: policy_el["vulnerability"]["score"], ""))
                            vul_desc = try_or_error(lambda: policy_el["vulnerability"]["description"], "")
                            vul_url = try_or_error(lambda: policy_el["vulnerability"]["url"], "")
                            vul_origin_url = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["url"], "")
                            vul_publish_date = try_or_error(lambda: policy_el["vulnerability"]["publishDate"], "")
                            vul_fix_resolution = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["fixResolution"],
                                                              "")
                            vul_fix_type = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["type"], "")
                            vul_fix_release_date = try_or_error(lambda: policy_el["vulnerability"]["topFix"]["date"], "")

                            exist_id = check_wi_id(id=vul_title,project_name=f"{prd_name}/{prj_name}")
                            if exist_id > 0:
                                wi_data, err_ = call_azure_api(api_type="GET", api=f"wit/workitems/{exist_id}",
                                                               data={}, project=conf.azure_project)
                            wi_type_ = try_or_error(lambda: wi_data["fields"]["System.WorkItemType"], "")
                            if exist_id == 0:
                                azure_operation = "add"
                            elif wi_type_.lower() != wi_type.lower():
                                call_azure_api(api_type="DELETE", api=f"wit//workitems/{exist_id}",
                                               data={}, project=conf.azure_project)
                                azure_operation = "add"
                            else:
                                azure_operation = "replace"
                            if exist_id not in updated_wi:
                                priority = set_priority(try_or_error(lambda: float(vul_score), 6)) if conf.priority.lower() == "true" else DEFAULT_PRIORITY
                                # Default priority is 2
                                lic_data = "<br>"
                                for lic_data_ in lic_data_arr:
                                    lic_data = lic_data + f"<a href='{lic_data_[2]}'>{lic_data_[1]}</a>" + \
                                               f"<br><b>License Reference File: </b><a href='{lic_data_[0]}'>{lic_data_[0]}</a><br>" \
                                               f"<b>License Policy Violation - </b>{policy_lic_name}<br>"
                                lic_data = generate_expandable_section("<b>License Details</b>", lic_data) if is_license else ""
                                vul_data = "" if is_license else \
                                    "<br><b>Vulnerability Details:</b> " + vul_desc + \
                                    "<br><b>Publish Date:</b> " + vul_publish_date + \
                                    f"<br><b>URL:</b> <a href='{vul_url}'>{vul_name}</a>" + \
                                    "<br><b>CVSS 3 Score Details </b>(" + str(vul_score) + ")" \
                                                                                           "<br><b>Suggested Fix:</b> " + \
                                    vul_fix_type + f"<br><b>Origin:</b> <a href='{vul_origin_url}'></a><br>" \
                                                   f"<b>Release Date:</b> " + vul_fix_release_date + \
                                    "<br><b>Fix Resolution:</b> " + vul_fix_resolution
                                hierarchy_libs = generate_html_bulleted_list(items=[x["filename"] for x in lib_hierarchy] if lib_dep == "Transitive" else list_dep_lib)

                                desc = "<b>Library - </b>" + lib_name + \
                                       "<br>" + lib_desc + \
                                       "<br><b>Path to dependency file: </b>" + path_dep + "<br><b>Path to library:</b>" + path_lib + \
                                       "<br><b>Vulnerable Library: </b>" + lib_name + \
                                       "<br><b>Dependency Hierarchy: </b><br>" + hierarchy_libs + \
                                       f"<br><b> Library home page: " \
                                       f"</b><a href='{lib_home_page}'>{lib_home_page}</a>" + vul_data + lic_data
                                create_wi_content(issue_id=issue_id)

        return f"{count_item} {conf.azure_type} work items created/updated for Mend project " \
               f"'{prj_name}' (Product '{prd_name}')" if count_item > 0 else \
            f"No {conf.azure_type} work items {status_op} for Mend project '{prj_name}' (Product '{prd_name}')"
    except Exception as err:
        return f"[{ex()}] Work item creation failed: {err}"


def run_sync(st_date: str, end_date: str, custom_flds: list, wi_type: str):
    global exist_wis
    res = []
    logger.info("Getting a modified project list")
    modified_projects = get_prj_list_modified(st_date, end_date)
    if conf.wsproducttoken:
        prd_list = conf.wsproducttoken.split(",")
        for prd_ in prd_list:
            data = json.dumps(
                {"requestType": "getAllProjects",
                 "userKey": conf.ws_user_key,
                 "orgToken": conf.ws_org_token,
                 "productToken": prd_,
                 })
            prj_lst_ = json.loads(call_ws_api(data=data))
            try:
                for prj_ in prj_lst_['projects']:
                    res.append(prj_['projectToken'])
            except Exception as err:
                logger.error(f"Mend API call failed. Details:{err}")
                exit(-1)

    if conf.wsprojecttoken:
        res.extend(conf.wsprojecttoken.split(","))
    res = set(modified_projects).intersection(res) if res else modified_projects
    res = list(set(res) - set(conf.wsexcludetoken.split(",")))
    #deleted_items = get_deleted_items()
    exist_wis = get_exist_wi()
    for prj_el in res:
        logger.info(create_wi(prj_el, st_date, end_date, custom_flds, wi_type))

    return f"{len(res)} project(s) processed" if res else "Nothing to create/update"


def get_deleted_items():
    del_lst = []
    try:
        r, errcode = call_azure_api(api_type="GET", api=f"wit/recyclebin", data={}, project=conf.azure_project)
        if errcode == 0:
            for res_ in r["value"]:
                del_lst.append(res_["id"])
    except Exception as err:
        logger.error(f"[{ex()}] Getting recycle bin items failed: {err}")
    return del_lst


def load_wi_json():
    global conf
    conf = startup() if not conf else conf
    conf.update_properties()
    load_el = conf.azure_type if conf.azure_type else "Task"
    r, errcode = call_azure_api(api_type="GET", api="wit/workitemtypes/", project=conf.azure_project, data={},
                                version="7.0", header="application/json")
    wi_list = []
    is_add = False
    if errcode == 0:
        for el_ in r["value"]:
            if el_["name"].lower() == load_el.lower():
                fields = []
                for el_fld_ in el_["fields"]:
                    flds, err = call_azure_api(api_type="GET", api=f"wit/fields/{el_fld_['referenceName']}", project=conf.azure_project, data={},
                                    version="7.0", header="application/json")
                    if err == 0:
                        is_add = (flds['type'].lower() == "string" or flds['type'].lower() == "html" or flds['type'].lower() == "double") \
                                 and not flds["isLocked"] and not flds["isPicklist"] and not flds["readOnly"]
                    if "Custom." in el_fld_["referenceName"] or el_fld_["alwaysRequired"] or is_add:
                        fields.append(
                            {"referenceName": el_fld_["referenceName"],
                             "name": el_fld_["name"],
                             "defaultValue": el_fld_["defaultValue"],
                             }
                        )
                wi_list.append(
                    {
                        "name": el_["name"],
                        "referenceName": el_["referenceName"],
                        "fields": fields
                    })
                break
    if not wi_list:
        logger.error(f"No work item types available for project '{conf.azure_project}'{r}")
        exit(-1)

    for res_ in wi_list:
        if res_["name"].lower() == load_el.lower():
            return load_el, res_["fields"]
    return load_el, []


def extract_url(url: str) -> str:
    url_ = url if url.startswith("https://") else f"https://{url}"
    url_ = url_.replace("http://", "")
    pos = url_.find("/", 8)
    return url_[0:pos] if pos > -1 else url_


def startup():
    global conf
    conf = Config(
        ws_user_key=varenvs.get_env("wsuserkey").strip(),
        ws_org_token=varenvs.get_env("wsapikey").strip(),
        ws_url=varenvs.get_env("wsurl").strip(),
        wsproducttoken=varenvs.get_env("wsproduct").strip(),
        wsprojecttoken=varenvs.get_env("wsproject").strip(),
        azure_uri=varenvs.get_env("wsazureuri").strip(),
        azure_pat=varenvs.get_env("wsazurepat").strip(),
        azure_project=varenvs.get_env("wsazureproject").strip(),
        reset=varenvs.get_env("wsreset", "False").strip(),
        wsexcludetoken=varenvs.get_env("wsexcludetoken").strip(),
        azure_area=varenvs.get_env("wsazurearea").strip(),
        azure_type=varenvs.get_env("wsazuretype", "Task").strip(),
        azure_custom=varenvs.get_env("wscustomfields").strip(),
        utc_delta=0,
        dependency=varenvs.get_env("wsdependency").strip(),
        reponame=varenvs.get_env("wsreponame").strip(),
        description=varenvs.get_env("azuredesc").strip(),
        priority=varenvs.get_env("azurepriority").strip(),
        wsalert=varenvs.get_env("wsalert").strip(),
        proxy=varenvs.get_env("proxy").strip(),
    )
    try:
        return conf
    except Exception as err:
        logger.error(f"[{ex()}] Configuration validation failed: {err}")
        exit(-1)
