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
from routing import (parse_route, build_table, coverage_report, LOUD_OUTCOMES,
                     SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_OK, SKIP_UNKNOWN)
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
max_wiql_page = 5000  # WIQL rows per page; Azure DevOps hard-caps a single result set at 20000
WARNING_MSG = False
API_VERSION = "1.4"
AGENT_INFO = {"agent": f"{__tool_name__.replace('_', '-')}", "agentVersion": __version__}
DEFAULT_PRIORITY = 2
uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
token_pattern = r"^[0-9a-zA-Z]{64}$"
azurearea = r"^[0-9a-zA-Z\s\-_]+$"
global_errors = 0
exist_wis = []
routed_targets = []
updated_wi = []
run_failed = False
mend_v2_session = None  # SessionInfo dict from POST /api/v2.0/login; JWT lives 10 minutes


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
    if conf.routing.lower() not in ("true", "false"):
        res.append(f"MEND_ROUTING must be 'true' or 'false', got '{conf.routing}'")
    if conf.routing.lower() == "true" and not [b for b in conf.branches.split(",") if b.strip()]:
        # An empty pattern list matches nothing, and branch-filtered is the quiet bucket —
        # so without this every project is skipped silently.
        res.append("MEND_BRANCHES must list at least one branch pattern when "
                   "MEND_ROUTING is enabled")
    if conf.routing.lower() == "true" and not conf.email:
        # Mend API 2.0 login (used by routing's paged sweep) requires an email; there is
        # no default, so this must be caught here rather than surfacing as a login failure.
        res.append("MEND_EMAIL must be set when MEND_ROUTING is enabled")
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
            info_el = r.pop()
            logger.error(f"[{fn()}] {info_el}")
            global_errors += 1
    else:
        logger.error(f"The Azure Project {conf.azure_project} was not found")
        global_errors += 1
    return errorcode


azure_project_page = 100


def iter_azure_projects():
    # Azure DevOps pages _apis/projects. The previous unpaginated call silently hid every
    # project past the first page, which at 107 projects broke get_lastrun/set_lastrun.
    # Yields pages; on failure it yields a terminal `None` sentinel (already logged) before
    # returning, so a consumer can tell "a later page failed" from "no more pages" instead of
    # silently treating a partial sweep as complete.
    skip = 0
    while True:
        r, errocode = call_azure_api(api_type="GET", api="projects", version="7.0",
                                     data={}, header="application/json",
                                     cmd_type=f"?$top={azure_project_page}&$skip={skip}&")
        if errocode != 0:
            logger.error(f"[{fn()}] Could not list Azure DevOps projects: {r}")
            yield None
            return
        page = try_or_error(lambda: r["value"], None)
        if page is None:
            logger.error(f"[{fn()}] Unexpected project list payload: {r}")
            yield None
            return
        yield page
        if len(page) < azure_project_page:
            return
        skip += azure_project_page


def get_azure_prj_id(prj_name: str):
    res = ""
    try:
        for page in iter_azure_projects():
            if page is None:
                continue
            for prj_ in page:
                if prj_["name"] == prj_name:
                    return prj_["id"]
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


def _resolve_project_names(tokens: list):
    """Map Mend 1.4 project token -> (productName, projectName).

    There is no 1.4 call that takes an arbitrary project token directly, and getAllProjects
    requires a productToken. So this enumerates products org-wide (getAllProducts, one call)
    and then each product's projects (getAllProjects, one call per product) until every
    requested token is resolved or the products run out — a handful of calls, not one per
    project. Returns None on any Mend API failure: a partial map here would silently make a
    real project look untagged rather than surface as an error.
    """
    wanted = set(tokens)
    if not wanted:
        return {}
    resolved = {}
    try:
        products = json.loads(call_ws_api(data=json.dumps(
            {"requestType": "getAllProducts",
             "userKey": conf.ws_user_key,
             "orgToken": conf.ws_org_token,
             })))["products"]
    except Exception as err:
        logger.error(f"[{ex()}] Getting product list for tag resolution failed: {err}")
        return None

    for prd in products:
        if len(resolved) == len(wanted):
            break
        prd_token = try_or_error(lambda: prd["productToken"], "")
        prd_name = try_or_error(lambda: prd["productName"], "")
        if not prd_token:
            continue
        try:
            projects = json.loads(call_ws_api(data=json.dumps(
                {"requestType": "getAllProjects",
                 "userKey": conf.ws_user_key,
                 "orgToken": conf.ws_org_token,
                 "productToken": prd_token,
                 })))["projects"]
        except Exception as err:
            logger.error(f"[{ex()}] Getting projects for product '{prd_name}' failed: {err}")
            return None
        for prj in projects:
            prj_token = try_or_error(lambda: prj["projectToken"], "")
            if prj_token and prj_token in wanted:
                resolved[prj_token] = (prd_name, try_or_error(lambda: prj["projectName"], ""))
    return resolved


def fetch_project_tags(tokens: list) -> dict:
    """Map Mend project token -> list of tag objects ({key|namespace, value}), per token, one of:

    - Resolved and scanned with tags -> the tag list.
    - Resolved but scanned with no tags, or absent from /entities, or unresolvable to a
      (product, project) name pair -> [] ("no-target": scanned/known but nothing to route on).
    - Resolved to a (product, project) name pair that collided with another project's in
      /entities -> None (ambiguous: ownership of the tags cannot be determined, so this must
      not be confused with a genuinely untagged project — see the duplicate-name-pair guard
      below). This is a per-token value, distinct from the function returning None outright.

    Returns None (the whole call, not a per-token value) if the Mend call failed, matching the
    get_exist_wi failure convention.

    1.4 project tokens and 2.0 /entities uuids are different identifier spaces (verified live:
    0 of 25 matched), so the join is done on (productName, projectName) instead — the same pair
    already carried in the Work Item tag. Names are resolved via _resolve_project_names().
    """
    names = _resolve_project_names(tokens)
    if names is None:
        return None

    tags_by_name = {}
    collided_names = set()
    page = 0
    page_size = 1000
    while True:
        payload, errorcode = call_ws_api_v2(f"orgs/{conf.ws_org_token}/entities",
                                            {"pageSize": page_size, "page": page})
        if errorcode != 0:
            return None
        rows = try_or_error(lambda: payload["retVal"], None)
        if rows is None:
            logger.error(f"[{fn()}] Unexpected /entities payload: {payload}")
            return None
        for row in rows:
            product_name = try_or_error(lambda: row["product"]["name"], "")
            project = try_or_error(lambda: row["project"], {})
            project_name = try_or_error(lambda: project["name"], "")
            key = (product_name, project_name)
            row_tags = try_or_error(lambda: project["tags"], [])
            if key in tags_by_name:
                # A duplicate (product, project) name pair makes the join ambiguous. Report it
                # loudly and mark it unusable rather than silently picking one of the two — the
                # per-token result below surfaces this as None, distinct from a plain [].
                logger.error(f"[{fn()}] Duplicate Mend project name pair "
                             f"'{product_name}/{project_name}' seen in /entities; refusing to "
                             f"guess which one owns the routing tags.")
                collided_names.add(key)
            else:
                tags_by_name[key] = row_tags
        # isLastPage is documented as a string ("true"/"false") but has been observed live as a
        # JSON bool. str(...).lower() handles both; the row-count check is belt-and-braces.
        is_last_page = str(try_or_error(lambda: payload["additionalData"]["isLastPage"], "")
                           ).lower() == "true"
        if is_last_page or len(rows) < page_size:
            break
        page += 1

    result = {}
    for token in tokens:
        name = names.get(token)
        if name is None:
            result[token] = []
        elif name in collided_names:
            result[token] = None
        else:
            result[token] = tags_by_name.get(name, [])
    return result


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


def _post_v2_login():
    # Split out so tests can stub the transport without mocking requests itself.
    # conf.api_url, NOT conf.ws_url: 2.0 lives on api-saas.mend.io while 1.4 lives on the
    # SCA app host. See the spec's servers block.
    url = f"{extract_url(conf.api_url)}/api/v2.0/login"
    body = {"email": conf.email, "userKey": conf.ws_user_key, "orgToken": conf.ws_org_token}
    try:
        res_ = requests.post(url, json=body, verify=False, proxies=conf.proxy,
                             headers={"Content-Type": "application/json"})
        return (json.loads(res_.text), 0) if res_.status_code == 200 \
            else (try_or_error(lambda: json.loads(res_.text), {}), 2)
    except Exception as err:
        return {f"[{ex()}] Mend 2.0 login failed": f"{err}"}, 2


def mend_v2_token() -> str:
    # Cached for the process. The JWT is valid for 10 minutes and all 2.0 use in this tool
    # is one burst at the start of a run, so expiry is handled by a single retry in
    # call_ws_api_v2 rather than by refresh-token plumbing.
    global mend_v2_session
    if mend_v2_session:
        return try_or_error(lambda: mend_v2_session["retVal"]["jwtToken"], "")
    payload, errorcode = _post_v2_login()
    if errorcode != 0:
        logger.error(f"[{fn()}] Mend API 2.0 login failed: {payload}")
        return ""
    token = try_or_error(lambda: payload["retVal"]["jwtToken"], "")
    if token:
        mend_v2_session = payload
    return token


def _get_v2(url: str, token: str, params: dict):
    try:
        res_ = requests.get(url, params=params or {}, verify=False, proxies=conf.proxy,
                            headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json"})
        if res_.status_code == 200:
            return json.loads(res_.text), 0
        return try_or_error(lambda: json.loads(res_.text), {}), res_.status_code
    except Exception as err:
        return {f"[{ex()}] Mend 2.0 call failed": f"{err}"}, 2


def call_ws_api_v2(api: str, params: dict = None):
    # Returns (payload, errorcode) with the same convention as call_azure_api:
    # 0 = success, non-zero = failure. One re-login covers a JWT that expired mid-run.
    global mend_v2_session
    url = f"{extract_url(conf.api_url)}/api/v2.0/{api}"
    payload, errorcode = _get_v2(url, mend_v2_token(), params)
    if errorcode in (401, 403):
        # The JWT lives 10 minutes. The spec documents no 401 anywhere, so an expired token
        # most plausibly surfaces as 403 — retry both. A real permission denial costs one
        # wasted re-login and still fails, which is the right trade.
        mend_v2_session = None
        payload, errorcode = _get_v2(url, mend_v2_token(), params)
    if errorcode != 0:
        logger.error(f"[{fn()}] Mend 2.0 call to '{api}' failed: {payload}")
        errorcode = 2
    return payload, errorcode


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


def mend_tag_predicate() -> str:
    # Every work item this tool creates carries exactly one policy tag from the Tags enum.
    # OR-ing them narrows the WIQL query from the customer's entire backlog down to items
    # this integration owns. See the plan's note on how that invariant is maintained.
    return " OR ".join([f'[System.Tags] CONTAINS "{t}"' for t in Tags.all_tags()])


def get_exist_wi():
    def retrieve_work_items(work_item_ids):
        work_items = []
        batch_size = 200  # This is maximum for running one bulk
        num_batches = (len(work_item_ids) + batch_size - 1) // batch_size

        for batch_index in range(num_batches):
            start_index = batch_index * batch_size
            end_index = min(start_index + batch_size, len(work_item_ids))
            batch_ids = work_item_ids[start_index:end_index]

            if not batch_ids:
                continue
            payload = {
                "ids": batch_ids,
                "fields": ["System.Id", "System.Title", "System.Tags", "System.WorkItemType"],  #"System.WorkItemType",
            }
            response, err = call_azure_api(api_type="POST", api="wit/workitemsbatch", version="6.0",
                                           data=payload, project=conf.azure_project, header="application/json")
            if err != 0:
                logger.error(f"[{fn()}] Work item batch hydration failed: {response}")
                return None
            work_items.extend([{x["fields"]["System.Title"]: {x["fields"]["System.Id"]: try_or_error(lambda: x["fields"]["System.Tags"],"")}} for x in response["value"]])
                               #if x["fields"]["System.WorkItemType"].lower() == conf.azure_type.lower()])

        return work_items

    global conf
    if conf is None:
        conf = startup()
        conf.update_properties()
    try:
        ids = []
        first_id = 0
        while True:
            data = {"query": f'select [System.Id] From WorkItems Where '
                             f'[System.TeamProject] = "{conf.azure_project}" '
                             f'And [System.Id] > {first_id} '
                             f'And ({mend_tag_predicate()}) '
                             f'And [System.State] <> "Removed" AND [System.State] <> "Deleted" '
                             f'ORDER BY [System.Id]'}
            r, errocode = call_azure_api(api_type="POST", api="wit/wiql", version="6.0",
                                         project=conf.azure_project, data=data,
                                         header="application/json",
                                         cmd_type=f"?$top={max_wiql_page}&")
            if errocode != 0:
                logger.error(f"[{fn()}] Could not read existing work items for "
                             f"'{conf.azure_project}': {r}")
                return None
            page = [x["id"] for x in r["workItems"]]
            if not page:
                break
            ids.extend(page)
            first_id = page[-1]
        return retrieve_work_items(work_item_ids=ids)
    except Exception as err:
        logger.error(f"[{ex()}] Could not read existing work items for "
                     f"'{conf.azure_project}': {err}")
        return None


def tag_set(raw_tags: str) -> set:
    # Azure DevOps returns System.Tags as "; "-delimited, while this tool writes them
    # comma-joined. Azure normalizes on write, so accepting both separators makes this
    # safe wherever it is called. Splitting is safe because neither character is legal
    # inside an Azure DevOps tag.
    return {t.strip() for t in (raw_tags or "").replace(",", ";").split(";") if t.strip()}


def check_wi_id(id: str, project_name: str):
    def owns(entry):
        # entry is {work_item_id: raw_tags}; a malformed entry must skip, not abort the search.
        # ';' joins multiple values so a tag at the end of one value can't weld onto the start
        # of the next; the needle is stripped since tag_set() only strips the haystack; both
        # sides are casefolded because Azure Boards tags are case-insensitive for identity
        # (case-preserving on first write, lowercased on read back), so an exact case-sensitive
        # comparison would miss an existing tag forever and create a duplicate every run.
        return try_or_error(lambda: project_name.strip().casefold() in
                             {t.casefold() for t in tag_set(';'.join(entry.values()))}, False)

    try:
        values = [d[id] for d in exist_wis if id in d and owns(d[id])]
        res = try_or_error(lambda: max(values, key=lambda x: list(x.keys())[0]), 0)
        if type(res) is dict:
            return list(res.keys())[0]
        else:
            return res
    except:
        return 0


def update_wi_in_thread():
    global conf, global_errors, run_failed
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
            if errocode != 0:
                logger.error(f"[{fn()}] Reverse sync WIQL query failed: {r}")
                global_errors += 1
                run_failed = True
                break
            results_wi = r["workItems"]
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
                if errcode != 0:
                    logger.error(f"[{fn()}] Reverse sync hydration failed for ids {id_str}: {wi}")
                    global_errors += 1
                    run_failed = True
                if errcode == 0:
                    for wq_el in wi['value']:
                        issue_id = wq_el['id']
                        issue_wi_title = wq_el['fields']['System.Title']
                        if tag_set(try_or_error(lambda: wq_el['fields']['System.Tags'], "")) & \
                                {tag_vul, tag_lic}:
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
        run_failed = True
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
                    exist_wis.append({vul_title: {r["id"]: ",".join(tags)}})
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
                info_el = r.pop()
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
                # err_ == 0 is required here: exist_id may be a work item created earlier in
                # this same run, and wi_data/err_ are not reset when exist_id == 0, so a stale
                # or transiently-failed (e.g. throttled) GET must not be read as "wrong type"
                # and trigger a DELETE of the item we just created.
                elif err_ == 0 and wi_type_.lower() != wi_type.lower():
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
                            # err_ == 0 is required here: exist_id may be a work item created
                            # earlier in this same run, and wi_data/err_ are not reset when
                            # exist_id == 0, so a stale or transiently-failed (e.g. throttled)
                            # GET must not be read as "wrong type" and trigger a DELETE of the
                            # item we just created.
                            elif err_ == 0 and wi_type_.lower() != wi_type.lower():
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


def list_azure_projects():
    # Returns None on failure so the caller can tell a real empty organization from a
    # call that did not happen or a partial sweep - a page failing after earlier pages
    # already succeeded must not be reported as the complete set.
    names = set()
    saw_page = False
    for page in iter_azure_projects():
        if page is None:
            return None
        saw_page = True
        names.update([x["name"] for x in page])
    return names if saw_page else None


def sync_had_fatal_error() -> bool:
    # A function, not a value: azure_wi_sync.py imports names at module load, so an
    # imported flag would be frozen at False (the same trap global_errors falls into).
    return run_failed


def expand_product_tokens(producttoken: str) -> list:
    # Shared by the legacy and routed paths. Two deliberate behaviour changes from the
    # inline block this replaces:
    #   1. No exit(-1) on failure — under routing, one bad product token must not kill
    #      every other target in the run.
    #   2. json.loads(call_ws_api(...)) is now inside the try. In the original it sat
    #      outside, so a non-200 from Mend returned "" and raised an uncaught
    #      JSONDecodeError instead of the graceful failure this refactor exists to give.
    res = []
    for prd_ in producttoken.split(","):
        data = json.dumps({"requestType": "getAllProjects",
                           "userKey": conf.ws_user_key,
                           "orgToken": conf.ws_org_token,
                           "productToken": prd_})
        try:
            prj_lst_ = json.loads(call_ws_api(data=data))
            for prj_ in prj_lst_['projects']:
                res.append(prj_['projectToken'])
        except Exception as err:
            logger.error(f"Mend API call failed. Details:{err}")
            return None
    return res


def run_sync_routed(modified_projects: list, st_date: str, end_date: str, custom_flds: list,
                    wi_type: str):
    global exist_wis, global_errors, routed_targets, run_failed
    # conf.azure_project, conf.reponame and conf.azure_area are all re-pointed per target
    # below and must be restored: main() still uses conf.azure_project for bookkeeping, and
    # create_area mutates azure_area cumulatively.
    original_azure_project = conf.azure_project
    original_reponame = conf.reponame
    original_azure_area = conf.azure_area

    tags = fetch_project_tags(modified_projects)
    if tags is None:
        global_errors += 1
        run_failed = True
        return "Aborted: could not read Mend project tags."

    known = list_azure_projects()
    if known is None:
        global_errors += 1
        run_failed = True
        return "Aborted: could not list Azure DevOps projects."
    # Azure project names are matched case-insensitively for lookup, but classify()'s
    # known_projects membership test is deliberately exact-string (routing.py stays dumb).
    # Normalise here, the only place that sees both the real Azure names and the raw tag
    # value, by rewriting each route's azure_project to the canonically-cased name before
    # classify() ever runs — that keeps classify()'s exact-match contract intact.
    known_by_casefold = {name.casefold(): name for name in known}

    # Tokens stop selecting targets and become scope narrowing, so a pilot can be limited
    # and MEND_EXCLUDETOKEN keeps working. Absent config narrows nothing.
    narrowed = set(modified_projects)
    scope = set()
    if conf.wsproducttoken:
        expanded = expand_product_tokens(conf.wsproducttoken)
        if expanded is None:
            # Failing to expand must never widen scope. An empty `scope` skips narrowing
            # entirely, which would route all ~400 projects and evaporate the pilot limit.
            global_errors += 1
            run_failed = True
            return "Aborted: could not expand MEND_PRODUCTTOKEN; refusing to widen scope."
        scope.update(expanded)
    if conf.wsprojecttoken:
        scope.update(conf.wsprojecttoken.split(","))
    if scope:
        narrowed &= scope
    excluded = set([t for t in conf.wsexcludetoken.split(",") if t]) & set(modified_projects)
    narrowed -= excluded

    # Distinguish the two reasons a project is out of scope: an operator excluded it on
    # purpose, versus it simply not being in the pilot's product/project scope.
    preset = {t: SKIP_EXCLUDED for t in excluded}
    preset.update({t: SKIP_OUT_OF_SCOPE
                   for t in (set(modified_projects) - narrowed) - excluded})

    # A per-token None from fetch_project_tags means the (product, project) name pair
    # collided in /entities and the join is ambiguous — distinct from a genuinely
    # untagged project ([]). That must surface loudly (SKIP_UNKNOWN, in LOUD_OUTCOMES),
    # never fall into the quiet no-target bucket that an empty route would produce.
    collided = set()
    routes = {}
    for token in modified_projects:
        per_token_tags = tags.get(token)
        if per_token_tags is None:
            collided.add(token)
            per_token_tags = []
        route = parse_route(per_token_tags)
        if route.azure_project:
            route.azure_project = known_by_casefold.get(route.azure_project.casefold(),
                                                         route.azure_project)
        routes[token] = route
    for token in collided:
        preset.setdefault(token, SKIP_UNKNOWN)

    targets, outcomes = build_table(routes, known, conf.branches, preset=preset)

    report = coverage_report(outcomes)
    routed = len([o for o in outcomes.values() if o == SKIP_OK])
    if outcomes and not routed:
        # Zero coverage is never normal once anything is tagged. This must also be FATAL:
        # logging at ERROR alone still lets main() advance the global watermark and print
        # "completed successfully" with exit 0, because global_errors is imported by value.
        global_errors += 1
        run_failed = True
        logger.error(f"{report} — nothing routed. Check MEND_BRANCHES "
                     f"('{conf.branches}') and the scan template's tag keys.")
    else:
        logger.info(report)
    for token, outcome in sorted(outcomes.items()):
        if outcome in LOUD_OUTCOMES:
            logger.error(f"Mend project {token}: {outcome} "
                         f"(destination '{routes[token].azure_project}')")
    unknown = len([o for o in outcomes.values() if o == SKIP_UNKNOWN])
    if unknown and routed and unknown >= routed:
        # Many unknown targets is more likely a PAT that cannot see those projects than
        # that many bad tags. We cannot prove it — call_azure_api collapses 403 and 404.
        logger.error(f"{unknown} destinations were not found in the organization. If they "
                     f"exist, the PAT may lack visibility into them.")

    # Populated as targets SUCCEED, not up front: the reverse sync uses this list to decide
    # whose Lastrun to advance, and a failed target must not have its window closed.
    routed_targets = []
    synced = 0
    for azure_project in sorted(targets):
        # Each Azure project is its own failure boundary: one bad target must not cost the
        # other 106. Backlog #6 owns turning this into a real per-target result object.
        conf.azure_project = azure_project
        conf.azure_area = original_azure_area
        exist_wis = get_exist_wi()
        if exist_wis is None:
            global_errors += 1
            run_failed = True
            exist_wis = []
            logger.error(f"Skipping Azure project '{azure_project}': could not read "
                         f"existing work items. Lastrun will not advance for it.")
            continue
        for token, route in targets[azure_project]:
            conf.reponame = route.repo
            logger.info(create_wi(token, st_date, end_date, custom_flds, wi_type))
            synced += 1
        routed_targets.append(azure_project)
        # Deliberately NO set_lastrun here. Lastrun is read by the reverse sync, which runs
        # after this (azure_wi_sync.py:60). Writing it now would close the window before it
        # is read and the reverse sync would push nothing back to Mend. Task 12 writes it.

    conf.azure_project = original_azure_project
    conf.reponame = original_reponame
    conf.azure_area = original_azure_area
    return f"{coverage_report(outcomes)}; {synced} Mend project(s) synced"


def run_sync(st_date: str, end_date: str, custom_flds: list, wi_type: str):
    global exist_wis, global_errors, run_failed
    run_failed = False
    res = []
    logger.info("Getting a modified project list")
    modified_projects = get_prj_list_modified(st_date, end_date)
    logger.info(f"Selection mode: {'tag-based routing' if conf.routing.lower() == 'true' else 'token list'}")
    if conf.routing.lower() == "true":
        return run_sync_routed(modified_projects, st_date, end_date, custom_flds, wi_type)
    if conf.wsproducttoken:
        expanded = expand_product_tokens(conf.wsproducttoken)
        if expanded is None:
            logger.error("Mend API call failed while expanding MEND_PRODUCTTOKEN.")
            exit(-1)
        res.extend(expanded)

    if conf.wsprojecttoken:
        res.extend(conf.wsprojecttoken.split(","))
    res = set(modified_projects).intersection(res) if res else modified_projects
    res = list(set(res) - set(conf.wsexcludetoken.split(",")))
    #deleted_items = get_deleted_items()
    exist_wis = get_exist_wi()
    if exist_wis is None:
        global_errors += 1
        run_failed = True
        exist_wis = []
        return (f"Aborted: could not read existing work items in Azure project "
                f"'{conf.azure_project}'. Skipping to avoid creating duplicates. "
                f"Lastrun will not advance; this window will be retried.")
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
        routing=varenvs.get_env("wsrouting").strip(),
        branches=varenvs.get_env("wsbranches").strip(),
        email=varenvs.get_env("wsemail").strip(),
        api_url=varenvs.get_env("wsapiurl").strip(),
    )
    try:
        return conf
    except Exception as err:
        logger.error(f"[{ex()}] Configuration validation failed: {err}")
        exit(-1)
