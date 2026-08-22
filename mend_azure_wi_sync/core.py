import inspect
import json
import logging
import os

import requests
import sys

sys.path.append(os.path.dirname(__file__))
from _version import __tool_name__, __version__
from config import *
from enrichment import format_epss, format_exploit, format_reachability
from identity import cve_key, license_title, matches_cve, matches_library, parse_cve_title
from reconcile import CLOSE, CREATE, REOPEN, SKIP, UPDATE, plan_actions
from routing import (parse_route, build_table, coverage_report, LOUD_OUTCOMES,
                     SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_OK, SKIP_UNKNOWN, SKIP_BRANCH)
from source3 import (library_url, license_policy_name, normalise_findings, normalise_licenses,
                     normalise_projects, normalise_violations, render_inputs, select_projects,
                     severity_floor)
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

conf = None
max_wi = 100
max_wiql_page = 5000  # WIQL rows per page; Azure DevOps hard-caps a single result set at 20000
WARNING_MSG = False
mend_v2_session = None
AGENT_INFO = {"agent": f"{__tool_name__.replace('_', '-')}", "agentVersion": __version__}
DEFAULT_PRIORITY = 2
uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
token_pattern = r"^[0-9a-zA-Z]{64}$"
azurearea = r"^[0-9a-zA-Z\s\-_]+$"
global_errors = 0
exist_wis = []
synced_projects = []   # [(project uuid, "Application/Project", azure_project)] appended by
                       # sync_project_v3
updated_wi = []
# Tracks which library keyId first claimed each exist_id this run, so a second library that
# happens to render the same title (see FINDING 1 in the strict-title review) can be detected
# instead of silently dropped by the `exist_id not in updated_wi` guard below.
wi_claim_keyid = {}
run_failed = False


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
    elif "/" in conf.azure_project:
        # Azure reads "{project}/{team}" and returns HTTP 500 — this is almost always a
        # $(System.TeamProject)-style value that picked up a team suffix by mistake.
        res.append(f"MEND_AZUREPROJECT ('{conf.azure_project}') must not contain '/' "
                   f"— Azure DevOps parses this as '{{project}}/{{team}}'")
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
    if conf.reachability.lower() not in ("true", "false"):
        res.append(f"MEND_REACHABILITY must be 'true' or 'false', got '{conf.reachability}'")
    return res


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


def reachability_enabled() -> bool:
    return conf.reachability.lower() == "true"


def epss_exploit_row_fields(policy_el: dict) -> dict:
    """The EPSS/Exploit row keys. Ungated: both values arrive inline with the Mend 3.0 finding,
    so there is nothing to spare an org by hiding them, and both always carry a value."""
    return {"EPSS": format_epss(policy_el), "Exploit": format_exploit(policy_el)}


def reachability_row_field(policy_el: dict, reachability_on: bool) -> dict:
    """The Reachability row key, gated on MEND_REACHABILITY alone."""
    return {"Reachability": format_reachability(policy_el)} if reachability_on else {}


def build_enrich_html(policy_el: dict, reachability_on: bool) -> str:
    """The enrichment lines spliced into a CVE's description. EPSS and Exploit Code Maturity
    always render; Reachability is gated on MEND_REACHABILITY, because it is blank for an org
    that has not enabled reachability analysis."""
    html = ""
    if reachability_on:
        html += f"<br><b>Reachability:</b> {format_reachability(policy_el)}"
    html += f"<br><b>EPSS:</b> {format_epss(policy_el)}" \
                f"<br><b>Exploit Code Maturity:</b> {format_exploit(policy_el)}"
    return html


def _post_v2_login():
    # Split out so tests can stub the transport without mocking requests itself.
    # mend_api_url(), NOT conf.ws_url: 2.0/3.0 live on api-saas.mend.io while conf.ws_url is
    # the SCA app host. See the spec's servers block.
    url = f"{mend_api_url()}/api/v2.0/login"
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
    global WARNING_MSG
    try:
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always", InsecureRequestWarning)
            res_ = requests.get(url, params=params or {}, verify=False, proxies=conf.proxy,
                                headers={"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"})
        if not WARNING_MSG:
            for warning in warning_list:
                if issubclass(warning.category, InsecureRequestWarning):
                    index_of_see = str(warning.message).find("See:")
                    logger.warning(str(warning.message)[:index_of_see].strip())
                    WARNING_MSG = True
        if res_.status_code == 200:
            return json.loads(res_.text), 0
        return try_or_error(lambda: json.loads(res_.text), {}), res_.status_code
    except Exception as err:
        return {f"[{ex()}] Mend 2.0 call failed": f"{err}"}, 2


def _post_v3(url: str, token: str, body: dict, params: dict):
    # Mirrors _get_v2's contract exactly (same InsecureRequestWarning one-shot suppression,
    # verify=False, proxies=conf.proxy, (payload, errorcode) return) -- the only difference is
    # the HTTP verb and that the payload travels as a JSON body instead of query params. This
    # exists because /projects/summaries is POST-only in the 3.0 spec while every other 3.0
    # endpoint in use is GET.
    global WARNING_MSG
    try:
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always", InsecureRequestWarning)
            res_ = requests.post(url, params=params or {}, json=body or {}, verify=False,
                                 proxies=conf.proxy,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"})
        if not WARNING_MSG:
            for warning in warning_list:
                if issubclass(warning.category, InsecureRequestWarning):
                    index_of_see = str(warning.message).find("See:")
                    logger.warning(str(warning.message)[:index_of_see].strip())
                    WARNING_MSG = True
        if res_.status_code == 200:
            return json.loads(res_.text), 0
        return try_or_error(lambda: json.loads(res_.text), {}), res_.status_code
    except Exception as err:
        return {f"[{ex()}] Mend 3.0 call failed": f"{err}"}, 2


def call_ws_api_v2(api: str, params: dict = None):
    # Returns (payload, errorcode) with the same convention as call_azure_api:
    # 0 = success, non-zero = failure. One re-login covers a JWT that expired mid-run.
    global mend_v2_session
    url = f"{mend_api_url()}/api/v2.0/{api}"
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


def call_ws_api_v3(api: str, params: dict = None, method: str = "GET", body: dict = None):
    # Same (payload, errorcode) convention as call_ws_api_v2. Mend 3.0 accepts the JWT
    # minted by the 2.0 login, so there is deliberately no separate 3.0 login path — but
    # 3.0 lives on the same API host as 2.0, not on the 1.4 SCA app host.
    #
    # method exists because the spec declares /projects/summaries as POST-only while every
    # other 3.0 endpoint in use is GET; cursor/limit still travel as query params either way
    # (the spec puts them `in: query` even on the POST), only the transport verb changes.
    global mend_v2_session
    url = f"{mend_api_url()}/api/v3.0/{api}"
    if method == "POST":
        payload, errorcode = _post_v3(url, mend_v2_token(), body or {}, params)
        if errorcode in (401, 403):
            mend_v2_session = None
            payload, errorcode = _post_v3(url, mend_v2_token(), body or {}, params)
    else:
        payload, errorcode = _get_v2(url, mend_v2_token(), params)
        if errorcode in (401, 403):
            mend_v2_session = None
            payload, errorcode = _get_v2(url, mend_v2_token(), params)
    if errorcode != 0:
        logger.error(f"[{fn()}] Mend 3.0 call to '{api}' failed: {payload}")
        errorcode = 2
    return payload, errorcode


# A server that keeps returning the same cursor would otherwise spin forever. 1000 pages at the
# default limit is 1,000,000 items -- far past any real project -- so hitting it means something
# is wrong, which is why it reports not-ok rather than returning what it collected.
MAX_V3_PAGES = 1000


def _v3_total_items_ok(api: str, items: list, payload: dict) -> bool:
    """Cross-check the collected item count against the server's `additionalData.totalItems`.

    totalItems is the only server-side evidence available that a walk was complete, so a genuine,
    parseable disagreement means the read was truncated (e.g. an empty page that still carried a
    cursor, or an empty first page from a mis-scoped org/project UUID). totalItems may be a
    string, may be missing, or may be malformed -- none of that is grounds to fail an otherwise
    legitimate read, so absence or a parse failure always falls back to True.
    """
    raw_total = try_or_error(lambda: payload["additionalData"]["totalItems"], None)
    if raw_total is None:
        return True
    try:
        total = int(raw_total)
    except (TypeError, ValueError):
        return True
    if total != len(items):
        logger.error(f"[{fn()}] Mend 3.0 call to '{api}' collected {len(items)} item(s) but "
                     f"totalItems reported {total}; treating the read as truncated and "
                     f"skipping closures.")
        return False
    return True


def fetch_v3_pages(api: str, params: dict = None, limit: int = 1000, method: str = "GET"):
    """Walk every cursor page of a 3.0 collection endpoint.

    Returns (items, ok). `ok` is False if ANY page failed, was malformed, the page cap was hit, a
    cursor repeated, or the collected count disagrees with the server's totalItems -- and it is
    load-bearing: reconciliation closes work items that are absent from a fetch, so a caller MUST
    treat ok=False as "I know nothing about this project" rather than as a shorter list. Returning
    the partial items alongside ok=False is deliberate: they are useful for creating and updating,
    which cannot do harm, while closure must be skipped entirely.

    method defaults to GET, unchanged for the two existing GET callers (findings/security,
    violations). Pass method="POST" for an endpoint like /projects/summaries that the spec
    declares POST-only; cursor/limit still ride as query params on the POST, per spec.
    """
    items = []
    cursor = None
    seen_cursors = set()
    for _ in range(MAX_V3_PAGES):
        page_params = dict(params or {})
        page_params["limit"] = limit
        if cursor is not None:
            page_params["cursor"] = cursor
        if method == "POST":
            payload, errorcode = call_ws_api_v3(api, page_params, method="POST", body={})
        else:
            payload, errorcode = call_ws_api_v3(api, page_params)
        if errorcode != 0:
            return items, False
        rows = try_or_error(lambda: payload["response"], None)
        if not isinstance(rows, list):
            logger.error(f"[{fn()}] Mend 3.0 call to '{api}' returned no 'response' list: {payload}")
            return items, False
        items.extend(rows)
        if not rows:
            # A cursor with no rows behind it is the end, however the server phrases it -- but an
            # empty page (including an empty first page) is exactly what a truncated or
            # mis-scoped read looks like, so it still needs the totalItems cross-check.
            return items, _v3_total_items_ok(api, items, payload)
        cursor = try_or_error(lambda: payload["additionalData"]["cursor"], None)
        if cursor is None:
            return items, _v3_total_items_ok(api, items, payload)
        if cursor in seen_cursors:
            logger.error(f"[{fn()}] Mend 3.0 call to '{api}' returned a repeated cursor; "
                         f"treating the read as failed rather than looping to the page cap.")
            return items, False
        seen_cursors.add(cursor)
    logger.error(f"[{fn()}] Mend 3.0 call to '{api}' exceeded {MAX_V3_PAGES} pages; "
                 f"treating the read as failed rather than trusting a truncated list.")
    return items, False


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
                "fields": ["System.Id", "System.Title", "System.Tags", "System.State",
                           "System.WorkItemType"],  #"System.WorkItemType",
            }
            response, err = call_azure_api(api_type="POST", api="wit/workitemsbatch", version="6.0",
                                           data=payload, project=conf.azure_project, header="application/json")
            if err != 0:
                logger.error(f"[{fn()}] Work item batch hydration failed: {response}")
                return None
            # System.State is carried so reconciliation can tell an open item from a closed one
            # without a second round trip; a closed item that looked absent would be recreated
            # as a duplicate and the original would never reopen.
            work_items.extend([{x["fields"]["System.Title"]: {x["fields"]["System.Id"]: {
                "tags": try_or_error(lambda x=x: x["fields"]["System.Tags"], ""),
                "state": try_or_error(lambda x=x: x["fields"]["System.State"], "")}}}
                for x in response["value"]])
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


def check_wi_id_matching(title_matches, project_name: str):
    """Find a live work item whose title satisfies `title_matches` and which carries
    `project_name` as a tag. Returns its id, or 0.

    `title_matches` is a predicate over the title so callers can match either an exact title or
    a legacy title shape (see identity.py) through one code path -- the tag-ownership rule below
    is the part that must not be duplicated.
    """
    def owns(entry):
        # entry is {work_item_id: {"tags": raw_tags, "state": state}}; a malformed entry must
        # skip, not abort the search.
        # ';' joins multiple values so a tag at the end of one value can't weld onto the start
        # of the next; the needle is stripped since tag_set() only strips the haystack; both
        # sides are casefolded because Azure Boards tags are case-insensitive for identity
        # (case-preserving on first write, lowercased on read back), so an exact case-sensitive
        # comparison would miss an existing tag forever and create a duplicate every run.
        return try_or_error(lambda: project_name.strip().casefold() in
                            {t.casefold() for t in tag_set(
                                ';'.join(v.get("tags", "") for v in entry.values()))}, False)

    try:
        values = []
        for d in exist_wis:
            for title, entry in try_or_error(lambda: list(d.items()), []):
                # A predicate raising on one odd title must not suppress a match elsewhere.
                if try_or_error(lambda: bool(title_matches(title)), False) and owns(entry):
                    values.append(entry)
        res = try_or_error(lambda: max(values, key=lambda x: list(x.keys())[0]), 0)
        if type(res) is dict:
            return list(res.keys())[0]
        else:
            return res
    except:
        return 0


def check_wi_id(id: str, project_name: str):
    return check_wi_id_matching(lambda title: title == id, project_name)


def classify_title(title: str):
    """A work item title -> (kind, key), or None if it is not one of ours.

    Inverts the three shipped title formats:
      "License Policy Violation detected in {lib}"             -> ("license", lib)
      "{lib}: {N} vulnerabilities (highest severity is {S})"   -> ("vulnerability", lib)
      "{CVE} ({Severity}) detected in {lib}"                   -> ("vulnerability", "{CVE}|{lib}")

    The key is the work item's IDENTITY, which is what differs between the two MEND_DEPENDENCY
    modes: dependency mode puts every CVE of a library on one work item, per-CVE mode puts each
    CVE on its own. Both the CVE and the library are in the per-CVE key -- the CVE alone collides
    when one CVE affects two libraries in a project, the library alone is dependency mode.

    The moving parts of every format are wildcards (the count, the max score, the severity word),
    because Mend rescores and a number baked into the key orphans the work item on the next run.

    A title matching NONE of the three returns None and is never adopted: a person's hand-created
    work item that happens to carry a Mend tag must not be closed by this tool.
    """
    text = (title or "").strip()
    prefix = "License Policy Violation detected in "
    if text.startswith(prefix):
        lib = text[len(prefix):].strip()
        return ("license", lib) if lib else None
    parsed = parse_cve_title(text)
    if parsed:
        return ("vulnerability", cve_key(*parsed))
    head = text.split(":", 1)[0].strip()
    if head and matches_library(text, head):
        return ("vulnerability", head)
    return None


def actual_work_items(project_name: str):
    """{(kind, key): {"id", "state"}} for the live work items belonging to one Mend project.

    The key is whatever classify_title decodes -- the library name in dependency mode, and
    "{cve}|{library}" in per-CVE mode -- so it matches the key fetch_v3_desired builds `desired`
    on. The two must agree exactly or reconciliation closes everything.

    The reverse of check_wi_id: that answers "does THIS title exist", this answers "what does
    Azure currently hold for this project". Reconciliation needs the second question.

    A title matching neither known format is IGNORED, never adopted. A person's hand-created work
    item that happens to carry the Mend tag must never be closed by this tool.
    """
    found = {}
    for entry_dict in exist_wis:
        for title, entry in try_or_error(lambda: list(entry_dict.items()), []):
            wid, meta = try_or_error(lambda: list(entry.items())[0], (None, None))
            if wid is None or not isinstance(meta, dict):
                continue
            if not try_or_error(lambda: project_name.strip().casefold() in
                                {t.casefold() for t in tag_set(meta.get("tags", ""))}, False):
                continue
            key = classify_title(title)
            if not key:
                continue
            candidate = {"id": wid, "state": meta.get("state", "")}
            previous = found.get(key)
            if previous is None:
                found[key] = candidate
                continue
            # Two live work items for one key. The winner is the LOWEST id, so the
            # choice is deterministic across runs rather than "whichever the cache listed last".
            # The loser is left alone -- we cannot tell which is canonical, and closing the wrong
            # one destroys a record an operator may be using. Leaving it open is today's
            # behaviour, so this is not a regression.
            keep, drop = sorted([previous, candidate],
                                key=lambda item: try_or_error(lambda: int(item["id"]),
                                                              float("inf")))
            logger.warning(f"[{fn()}] Two work items share the key {key} in project "
                           f"{project_name}: {previous.get('id')} and {candidate.get('id')}. "
                           f"Reconciling against {keep.get('id')} (the lowest id); "
                           f"{drop.get('id')} is left untouched -- resolve the duplicate by hand.")
            found[key] = keep
    return found


def _patch_state(work_item_id, state: str, verb: str) -> bool:
    """PATCH System.State and NOTHING else.

    Deliberately not a description rewrite: this path has no enrichment join, so rewriting the
    description would blank the EPSS and reachability columns (observed live), and a closed work
    item is a record worth preserving exactly as the operator last saw it.
    """
    data = [{"op": "replace", "path": "/fields/System.State", "value": state}]
    try:
        response, errorcode = call_azure_api(api_type="PATCH", api=f"wit/workitems/{work_item_id}",
                                             data=data, project=conf.azure_project)
        if errorcode != 0:
            logger.error(f"[{fn()}] Could not {verb} work item {work_item_id} to state "
                         f"'{state}': {response}. This one item is left as it was; the run "
                         f"continues.")
            return False
        logger.info(f"[{fn()}] Work item {work_item_id} {verb}d ({state})")
        return True
    except Exception as err:
        logger.error(f"[{ex()}] Could not {verb} work item {work_item_id}: {err}")
        return False


def apply_close(work_item_id, state: str) -> bool:
    return _patch_state(work_item_id, state, "close")


def apply_reopen(work_item_id, state: str) -> bool:
    return _patch_state(work_item_id, state, "reopen")


def per_cve_mode() -> bool:
    """MEND_DEPENDENCY=false -- one work item per CVE instead of one per library.

    The ONE place conf.dependency is turned into a boolean, so grouping (fetch_v3_desired),
    rendering (render_entry_v3) and matching (write_wi_v3) can never disagree about which mode
    the run is in. Disagreement means the key `desired` is built on is not the key closure
    decodes, and reconciliation then closes every work item in the project.

    Config.update_properties defaults an unset MEND_DEPENDENCY to "True", so anything that is not
    "true" is per-CVE -- the same test render_entry_v3 has always applied.
    """
    return str(getattr(conf, "dependency", "")).lower() != "true"


def run_severity_floor() -> float:
    """The ONE severity floor for this run -- the shared accessor creation and closure both read.

    MEND_SEVERITY now decides which findings earn a work item AND which findings hold one open.
    Those two answers MUST come from the same number: if creation filters at 7.0 and closure at
    0.0 (or the reverse) every work item between the two thresholds is created, immediately
    closed, and re-created on the next run -- flapping forever. Never call severity_floor() on
    conf directly from the run path; call this.
    """
    return severity_floor(getattr(conf, "severity", ""))


def reconcile_project(project, floor=None, desired=None, ok=None):
    """Reconcile ONE Mend project against Azure. Returns (created, updated, closed, reopened,
    skipped).

    CREATE and UPDATE are counted and reported but deliberately NOT executed here: creation is
    create_wi_v3's job, and sync_project_v3 runs the two halves in order off ONE 3.0 read at ONE
    severity floor. This function is only the closure half.

    The closure interlock (spec 6.1): on ok=False from fetch_v3_desired NOTHING is closed. An
    incomplete read is indistinguishable from a project whose findings were all remediated, and
    acting on that at this customer's scale is a mass-closure event. REOPEN still runs -- it
    cannot destroy anything.

    SKIP makes no API call at all: see reconcile.plan_actions.

    MEND_SEVERITY is LIVE here. `floor` defaults to run_severity_floor() -- the same accessor
    the creation path reads -- and sync_project_v3 passes the floor it created with, together
    with the very `desired`/`ok` pair it created from, so creation and closure decide on one
    snapshot filtered at one threshold. A floor here that differs from the creation floor makes
    every work item between the two thresholds created, closed and re-created every run.
    """
    project_name = f"{project.get('application_name', '')}/{project.get('name', '')}"
    closed_state = normalise_state(getattr(conf, "closed_state", ""), "Closed")
    reopen_state = normalise_state(getattr(conf, "reopen_state", ""), "New")
    if floor is None:
        floor = run_severity_floor()

    # `actual` is read from the exist_wis cache. When sync_project_v3 calls this it has already
    # written this project's work items, so entries it just created/updated are present with the
    # state Azure returned on the write. That is safe in one direction only: everything written
    # this run came FROM `desired`, so nothing written can be missing from `desired` and be
    # closed. A write whose response carried no state caches "" -- read as "not closed", which
    # can only miss a reopen, never cause a close.
    actual = actual_work_items(project_name)
    if desired is None or ok is None:
        # Standalone call (no caller-supplied snapshot): read it here, at the SAME floor.
        desired, ok = fetch_v3_desired(project.get("uuid", ""), floor)

    if not ok:
        logger.warning(f"[{fn()}] The Mend read for project {project_name} was incomplete. "
                       f"Closures are SKIPPED for this project -- a partial read looks exactly "
                       f"like a project whose findings were all remediated, and closing on it "
                       f"would be a mass-closure. Reopens and the rest of the run continue.")

    # Key-space interlock. `actual` keys come from work item TITLES (1.4 builds them from
    # library.filename); `desired` keys come from 3.0 component.name / originName. Those two
    # spellings have never been verified byte-identical. If they differ at all, every `actual`
    # key misses and EVERY work item in the project is closed, then re-created by 1.4 next run.
    # Both sides non-empty with zero overlap is not a project that was fully remediated -- that
    # case has an EMPTY `desired`, and its closures must still run.
    if desired and actual and not (set(desired) & set(actual)):
        logger.error(f"[{fn()}] Suspected key-space mismatch in project {project_name}: "
                     f"{len(desired)} Mend finding(s) and {len(actual)} work item(s), and NOT "
                     f"ONE key in common. Closures are SKIPPED for this project. Example Mend "
                     f"keys: {sorted(map(str, desired))[:2]}. Example work item keys: "
                     f"{sorted(map(str, actual))[:2]}. If those two spellings differ, that is "
                     f"the bug -- not a remediated project.")
        ok = False

    created = updated = closed = reopened = skipped = 0
    for action in plan_actions(desired, actual, closed_state):
        verb = action.get("action")
        if verb == CREATE:
            created += 1
        elif verb == UPDATE:
            updated += 1
        elif verb == REOPEN:
            if apply_reopen(action.get("id"), reopen_state):
                reopened += 1
        elif verb == CLOSE:
            if not ok:
                continue
            if apply_close(action.get("id"), closed_state):
                closed += 1
        elif verb == SKIP:
            skipped += 1

    logger.info(f"[{fn()}] Reconciled {project_name}: {created} to create, {updated} to update "
                f"(neither is executed on this path), {closed} closed, {reopened} reopened, "
                f"{skipped} already closed and skipped.")
    return created, updated, closed, reopened, skipped


def reconcile_after_sync():
    """Close work items whose Mend findings are gone, for every project synced this run.

    Runs AFTER the forward sync, off `synced_projects` -- the (prj_token, "Product/Project",
    azure_project) tuples sync_project_v3 appends. That third element is the join that makes this
    routing-safe: run_sync_routed re-points conf.azure_project per target, so the Azure project a
    Mend project was written to is the only one its work items may be closed in.
    """
    global conf, global_errors
    conf = startup() if not conf else conf
    conf.update_properties()
    logger.info(f"[{fn()}] Reconciliation starting for {len(synced_projects)} synced "
                f"project(s): work items whose Mend finding is gone move to MEND_CLOSEDSTATE, "
                f"and items whose finding came back move to MEND_REOPENSTATE.")

    original_azure_project = conf.azure_project
    try:
        projects, ok = fetch_v3_projects()
        if not ok:
            logger.error(f"[{fn()}] Could not read the Mend project list. NOTHING is closed this "
                         f"run: a partial list makes a project we simply failed to read look "
                         f"exactly like one whose findings are all gone.")
            return

        lookup = {}
        for project in projects or []:
            key = f"{project.get('application_name', '')}/{project.get('name', '')}".casefold()
            lookup[key] = project

        closed = reopened = skipped = matched = unmatched = 0
        for prj_token, product_project, azure_project in list(synced_projects):
            project = lookup.get(str(product_project).casefold())
            if not project:
                unmatched += 1
                logger.warning(f"[{fn()}] Mend project '{product_project}' was synced this run "
                               f"but is not in the Mend 3.0 project list. It is SKIPPED -- "
                               f"guessing which 3.0 project it is could close work items "
                               f"belonging to a different project.")
                continue
            try:
                # Per-project Azure target, restored afterwards. Leaking one project's target
                # into the next closes work items in the wrong Azure project.
                conf.azure_project = azure_project
                _, _, prj_closed, prj_reopened, prj_skipped = reconcile_project(project)
                closed += prj_closed
                reopened += prj_reopened
                skipped += prj_skipped
                matched += 1
            except Exception as err:
                global_errors += 1
                logger.error(f"[{ex()}] Reconciliation failed for '{product_project}': {err}. "
                             f"The remaining projects are still reconciled.")
            finally:
                conf.azure_project = original_azure_project

        logger.info(f"[{fn()}] Reconciliation summary: {closed} work item(s) closed, "
                    f"{reopened} reopened, {skipped} already closed and skipped; "
                    f"{matched} project(s) reconciled, {unmatched} unmatched and skipped.")
    except Exception as err:
        global_errors += 1
        logger.error(f"[{ex()}] Reconciliation did not complete: {err}. The forward sync that "
                     f"already succeeded is unaffected.")
    finally:
        conf.azure_project = original_azure_project


# The work item rendering helpers below were nested inside the deleted 1.4 create_wi. They were
# lifted to module level UNCHANGED so the 3.0 creation path (create_wi_v3) reuses the exact same
# renderers rather than reimplementing them -- two implementations of a shipped work item
# description would drift.


def set_priority(value: float):
    score = [70, 55, 40]  # Mend gradation of SCC scores
    z = value * 10
    i = 0
    for i, sc_ in enumerate(score):
        if z // sc_ == 1:
            break
    return i + 1


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
                    # Must be reset per '&'-delimited part. Without it, a part naming an
                    # unknown or RETIRED variable ($MEND_EMAIL, until it was deleted with
                    # the 2.0 transport) leaks the PREVIOUS part's var_name and duplicates
                    # its value -- which can be $MEND_USERKEY. "" resolves to "" via
                    # try_or_error, which is what an unmatched part has always produced.
                    var_name = ""
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


def generate_expandable_section(summary, detail):
    html = f"<details>\n"
    html += f"  <summary>{summary}</summary>\n"
    html += f"  <p>{detail}</p>\n"
    html += f"</details>"
    return html


def generate_html_bulleted_list(items):
    html = "<ul>\n"
    for item in items:
        html += f"  <li>{item}</li>\n"
    html += "</ul>"
    return html


def get_field_ref(fld_name, cstm_flds):
    for c_fld_ in cstm_flds:
        if fld_name == c_fld_["name"]:
            return f"/fields/{c_fld_['referenceName']}"
    return f"/fields/Custom.{fld_name}"


def build_wi_tags(project_tag: str, policy_tag: str, routing: str, reponame: str) -> list:
    # Repo identity is a work item tag because the client declined Area Path. Taking the
    # values as arguments keeps this testable without constructing a whole Config.
    tags = [project_tag, policy_tag]
    if routing.lower() == "true" and reponame:
        tags.append(reponame)
    return tags



def build_enrich_html_v3(row: dict, reachability_on: bool) -> str:
    """The enrichment lines spliced into a 3.0 CVE section.

    ASYMMETRY, DELIBERATE. EPSS and Exploit Code Maturity render UNCONDITIONALLY here: the
    MEND_EPSS gate existed because 1.4 had to pay an extra getProjectAlertsByType call per
    project to learn them, so an org that did not want the columns should not pay for them. On
    3.0 both values arrive inline with the finding at no cost, so gating them only buys an
    operator a missing column.

    MEND_REACHABILITY stays a gate. Reachability is blank for an org that has not enabled
    reachability analysis, and the toggle spares them a column of dashes.
    """
    html = ""
    if reachability_on:
        html += f"<br><b>Reachability:</b> {row.get('reachability', '')}"
    html += f"<br><b>EPSS:</b> {row.get('epss', '')}" \
            f"<br><b>Exploit Code Maturity:</b> {row.get('maturity', '')}"
    return html


def build_license_html_v3(licenses: list, policy_name: str) -> str:
    """The <details> License Details block, same shape the 1.4 path renders it in.

    `licenses` is the list Task 2 attaches to every entry ({"name", "url", "reference_file"}).
    """
    lic_data = ""
    for lic_ in licenses or []:
        ref_ = lic_.get("reference_file", "") if isinstance(lic_, dict) else ""
        name_ = lic_.get("name", "") if isinstance(lic_, dict) else ""
        url_ = lic_.get("url", "") if isinstance(lic_, dict) else ""
        lic_data = lic_data + f"<a href='{url_}'>{name_}</a>" + \
            f"<br><b>License Reference File: </b><a href='{ref_}'>{ref_}</a><br>" \
            f"<b>License Policy Violation - </b>{policy_name}<br>"
    return generate_expandable_section("<b>License Details</b>", lic_data)


def max_score_v3(rows: list) -> str:
    """The highest CVSS score across a library's findings, as it appears in the title.

    Returned as the RAW value, not a reformatted float: the title is the match key's carrier and
    "9.8" must not become "9.80". "" when nothing is scored -- identity.matches_library tolerates
    an empty score group precisely for this case.
    """
    best, best_val = "", None
    for row in rows or []:
        raw = row.get("score", "")
        value = try_or_error(lambda raw=raw: float(raw), None)
        if value is None:
            continue
        if best_val is None or value > best_val:
            best, best_val = raw, value
    return best


def vuln_section_v3(row: dict, inputs: dict, reachability_on: bool) -> str:
    """One CVE's <details> body, mirroring the 1.4 per-CVE section field for field."""
    return "<b>Vulnerable Library:</b>" + inputs["library"] + \
        "<br><b>Path to dependency file: </b>" + inputs["dependency_file"] + \
        "<br><b>Path to library:</b>" + inputs["library_path"] + \
        "<br><b>Vulnerability Details:</b> " + row.get("description", "") + \
        "<br><b>Publish Date:</b> " + row.get("publish_date", "") + \
        f"<br><b>URL:</b> <a href='{row.get('url', '')}'>{row.get('name', '')}</a>" + \
        "<br><b>CVSS 3 Score Details </b>(" + str(row.get("score", "")) + ")" + \
        build_enrich_html_v3(row, reachability_on) + \
        "<br><b>Suggested Fix:</b> " + row.get("fix_type", "") + \
        f"<br><b>Origin:</b> <a href='{row.get('fix_url', '')}'></a><br>" \
        f"<b>Release Date:</b> " + row.get("fix_date", "") + \
        "<br><b>Fix Resolution:</b> " + row.get("fix_resolution", "")


def library_block_v3(inputs: dict, with_hierarchy: bool) -> str:
    """The library header block both MEND_DEPENDENCY branches open their description with."""
    block = "<b>Library - </b>" + inputs["library"] + \
        "<br>" + inputs["description"] + \
        "<br><b>Path to dependency file: </b>" + inputs["dependency_file"] + \
        "<br><b>Path to library:</b>" + inputs["library_path"] + \
        "<br><b>Vulnerable Library: </b>" + inputs["library"]
    if with_hierarchy:
        block += "<br><b>Dependency Hierarchy: </b><br>" + \
                 generate_html_bulleted_list(items=inputs["parents"])
    home = inputs["home_page"]
    return block + f"<br><b> Library home page: </b><a href='{home}'>{home}</a>"


def render_entry_v3(kind: str, library: str, entry: dict, reachability_on: bool) -> list:
    """One `desired` entry -> the work items it should produce, as
    [{"title", "desc", "score", "exact"}, ...].

    Rendering is split out of create_wi_v3 so the HTML and, far more importantly, the TITLES can
    be tested without an Azure DevOps double.

    TITLES ARE A CONTRACT, not cosmetics. Every title here must round-trip through
    classify_title back to the (kind, library) key it was built for, because Plan 4's closure
    reads Azure by title and closes on the key it decodes. A title that does not round-trip
    either strands a work item open forever or closes somebody else's.

    "exact" says how the item is matched against what Azure already holds. Only a LICENCE title
    is matched exactly -- it has no moving parts. A dependency-mode title carries a finding count
    and a max score and a per-CVE title carries a severity word; all three move on a rescore, so
    those match on identity instead (identity.matches_library / identity.matches_cve). A per-CVE
    item also carries "cve", which is what picks the second matcher.
    """
    inputs = render_inputs(entry)
    rows = inputs["vulnerabilities"]
    licenses = entry.get("licenses") or [] if isinstance(entry, dict) else []

    if kind == "license":
        desc = library_block_v3(inputs, with_hierarchy=False) + \
            build_license_html_v3(licenses, license_policy_name(entry))
        return [{"title": license_title(library), "desc": desc, "score": "", "exact": True}]

    if not per_cve_mode():
        if not rows:
            return []
        table_data = []
        sections = ""
        for row in rows:
            # URL must stay the LAST key written: create_html_table renders the first column as
            # a link to row["URL"] and drops the final cell by position, so any key after URL
            # vanishes from the table.
            table_row = {
                "CVE": row.get("name", ""),
                "Severity": row.get("severity", ""),
                "CVSS": row.get("score", ""),
                "EPSS": row.get("epss", ""),
                "Exploit": row.get("maturity", ""),
                "Dependency": inputs["library"],
                "Type": inputs["dependency_type"],
                "Fixed in": row.get("fix_resolution", ""),
            }
            if reachability_on:
                table_row["Reachability"] = row.get("reachability", "")
            table_row["URL"] = row.get("url", "")
            table_data.append(table_row)
            sections += generate_expandable_section(row.get("name", ""),
                                                    vuln_section_v3(row, inputs, reachability_on))
        # len(entry["findings"]) rather than len(rows): the count in the title is the number of
        # findings the entry holds, and the two are one-to-one by construction (_vulnerabilities
        # emits exactly one row per finding).
        count = len(entry.get("findings") or []) if isinstance(entry, dict) else len(rows)
        max_severity = max_score_v3(rows)
        title = f"{library}: {count} vulnerabilities (highest severity is {max_severity})"
        desc = generate_expandable_section(f"Vulnerable library - {library}",
                                           library_block_v3(inputs, with_hierarchy=True)) + \
            "<br>" + create_html_table(data=table_data) + "<b>Details:</b><br>" + sections
        return [{"title": title, "desc": desc, "score": max_severity, "exact": False}]

    items = []
    for row in rows:
        vul_name = row.get("name", "")
        if not vul_name:
            continue
        severity = str(row.get("severity", "")).capitalize()
        desc = library_block_v3(inputs, with_hierarchy=True) + \
            vuln_section_v3(row, inputs, reachability_on)
        items.append({"title": f"{vul_name} ({severity}) detected in {library}",
                      "desc": desc, "score": row.get("score", ""), "exact": False,
                      "cve": vul_name})
    return items


def write_wi_v3(item: dict, tags: list, lib_url: str, cstm_flds: list, wi_type: str,
                project_name: str):
    """Create or update ONE work item from a rendered 3.0 item. Returns "created", "updated"
    or "failed".

    Matching, the wrong-type DELETE-and-recreate, and the exist_wis cache refresh are all
    identical to the deleted 1.4 path's -- both must agree on which work item a title
    identifies, or the changeover in Task 4 orphans every item the 1.4 path created.
    """
    global global_errors, exist_wis, updated_wi
    title = item["title"]
    if item["exact"]:
        exist_id = check_wi_id(id=title, project_name=project_name)
    elif item.get("cve"):
        # Per-CVE mode: the severity word in the title moves on a rescore, so the item is found
        # by CVE + library -- the same key classify_title decodes for closure. Matching the title
        # exactly here would create a duplicate on every rescore and strand the original open.
        exist_id = check_wi_id_matching(
            lambda t: matches_cve(t, item["cve"], item["library"]), project_name=project_name)
    else:
        exist_id = check_wi_id_matching(lambda t: matches_library(t, item["library"]),
                                        project_name=project_name)
    wi_data, err_ = {}, 2
    if exist_id > 0:
        wi_data, err_ = call_azure_api(api_type="GET", api=f"wit/workitems/{exist_id}",
                                       data={}, project=conf.azure_project)
    wi_type_ = try_or_error(lambda: wi_data["fields"]["System.WorkItemType"], "")
    if exist_id == 0:
        azure_operation = "add"
    # err_ == 0 is required: a transiently-failed (e.g. throttled) GET must not be read as
    # "wrong type" and trigger a DELETE of a work item that is perfectly fine.
    elif err_ == 0 and wi_type_.lower() != wi_type.lower():
        call_azure_api(api_type="DELETE", api=f"wit//workitems/{exist_id}",
                       data={}, project=conf.azure_project)
        azure_operation = "add"
    else:
        azure_operation = "replace"

    if exist_id > 0 and exist_id in updated_wi:
        # Two Mend projects routed to one Azure project can both hold the same library. The
        # second write would overwrite the first with its own project's content; skip it and
        # say so rather than letting the work item flip contents run to run.
        logger.warning(f"[{fn()}] Work item {exist_id} ('{title}') was already written this "
                       f"run; skipping the duplicate write for {project_name}.")
        return "skipped"

    data = [
        {"op": azure_operation, "path": "/fields/System.Title", "value": title},
        {"op": azure_operation, "path": "/fields/Microsoft.VSTS.Common.Priority",
         "value": item["priority"]},
        {"op": azure_operation, "path": "/fields/System.Tags", "value": ",".join(tags)},
    ]
    if conf.description == "Description":
        desc_field = "/fields/System.Description"
    elif conf.description == "ReproSteps":
        desc_field = "/fields/Microsoft.VSTS.TCM.ReproSteps"
    elif conf.description:
        desc_field = get_field_ref(conf.description, cstm_flds)
    else:
        desc_field = ""
    if desc_field:
        data.append({"op": azure_operation, "path": desc_field, "value": item["desc"]})

    for custom_ in cstm_flds:
        fld_name, fld_val = analyze_fields(custom_, item["source"])
        if fld_val and not any(fld_name in el_["path"] for el_ in data):
            data.append({"op": "add", "path": f"/fields/{fld_name}", "value": fld_val})
        elif not fld_val and "Custom." in fld_name:
            data.append({"op": "remove", "path": f"/fields/{fld_name}"})

    if conf.azure_area:
        create_area(conf.azure_area)
        data.append({"op": azure_operation, "path": "/fields/System.AreaPath",
                     "value": f"{conf.azure_area}"})

    try:
        if azure_operation == "add":
            if lib_url:
                # The operator's one click from the work item to the library in Mend.
                # Deliberately NO attributes.comment -- that carried "{projectToken},{issueUuid}"
                # for the reverse sync, which no longer exists and nothing reads.
                data.append({"op": "add", "path": "/relations/-",
                             "value": {"rel": "Hyperlink", "url": lib_url}})
            r, errcode = call_azure_api(api_type="POST", api=f"wit/workitems/${wi_type}",
                                        data=data, project=conf.azure_project)
            status_op = "created"
        else:
            r, errcode = call_azure_api(api_type="PATCH", api=f"wit/workitems/{exist_id}",
                                        data=data, project=conf.azure_project)
            status_op = "updated"
        if errcode == 0:
            claimed_id = exist_id if exist_id > 0 else try_or_error(lambda: r["id"], 0)
            if claimed_id:
                # A PATCH can rename the item, and exist_wis is read again later this same run,
                # so the stale entry is replaced rather than left cached under its old title.
                for d in list(exist_wis):
                    if claimed_id in try_or_error(lambda d=d: list(d.values())[0], {}):
                        exist_wis.remove(d)
                exist_wis.append({title: {claimed_id: {
                    "tags": ",".join(tags),
                    "state": try_or_error(lambda: r["fields"]["System.State"], "")}}})
                updated_wi.append(claimed_id)
            logger.info(f"{conf.azure_type} {try_or_error(lambda: r['id'], claimed_id)} {status_op}")
            return status_op
        if errcode == 1:
            logger.warning(f"{conf.azure_type} creation/update failed: "
                           f"{try_or_error(lambda: r['message'], r)}")
        else:
            logger.error(f"[{fn()}] {try_or_error(lambda: r.pop(), r)}")
        return "failed"
    except Exception as err:
        logger.error(f"[{ex()}] Work item creation/update failed: {err}")
        global_errors += 1
        return "failed"


def create_wi_v3(project, desired: dict, cstm_flds: list, wi_type: str):
    """Create and update Azure work items from one project's 3.0 `desired` state.

    Returns (created, updated, failed). It renders the SAME work items the deleted 1.4 path
    rendered -- same renderers, same title matching, same tags -- so a backlog created by that
    path is picked up rather than duplicated.
    """
    global conf
    conf = startup() if not conf else conf
    project_name = f"{project.get('application_name', '')}/{project.get('name', '')}"
    reachability_on = reachability_enabled()
    created = updated = failed = 0
    for (kind, key), entry in (desired or {}).items():
        # The KEY is the work item's identity ("{cve}|{lib}" in per-CVE mode); the LIBRARY is what
        # the renderers need. They are the same string only in dependency mode, so the library is
        # read off the entry rather than taken apart from the key.
        library = (entry.get("library") if isinstance(entry, dict) else "") or key
        try:
            tags = build_wi_tags(
                project_name,
                Tags.get_el_by_name("LICENSE" if kind == "license" else "VULNERABILITY_SCORE"),
                conf.routing, conf.reponame)
            lib_url = library_url(entry)
            for item in render_entry_v3(kind, library, entry, reachability_on):
                if not item["desc"]:
                    continue
                item["library"] = library
                item["source"] = entry
                item["priority"] = set_priority(
                    try_or_error(lambda item=item: float(item["score"]), 6)) \
                    if conf.priority.lower() == "true" else DEFAULT_PRIORITY
                outcome = write_wi_v3(item, tags, lib_url, cstm_flds, wi_type, project_name)
                if outcome == "created":
                    created += 1
                elif outcome == "updated":
                    updated += 1
                elif outcome == "failed":
                    failed += 1
        except Exception as err:
            failed += 1
            logger.error(f"[{ex()}] Work item creation failed for "
                         f"{kind} '{key}' in {project_name}: {err}")
    logger.info(f"[{fn()}] {project_name}: {created} work item(s) created, {updated} updated, "
                f"{failed} failed.")
    return created, updated, failed


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


def error_count() -> int:
    # Mirrors sync_had_fatal_error(): azure_wi_sync.py must call this rather than import
    # global_errors by value, or its "completed successfully" check is frozen at 0 forever.
    return global_errors


def sync_project_v3(project, floor: float, custom_flds: list, wi_type: str) -> bool:
    """Create/update AND reconcile ONE Mend project, from ONE 3.0 read at ONE severity floor.

    The whole point of doing both here: `desired` and `ok` are fetched once and handed to both
    halves. Creation writes exactly the entries that pass `floor`; closure closes exactly the
    work items those entries do not account for. Two reads at two floors is the flapping bug --
    see run_severity_floor.

    ok=False (a partial Mend read) still creates and updates -- neither can destroy anything --
    and reconcile_project closes NOTHING. That interlock lives there, untouched.

    A failure here is per project: it is logged, counted, and the run continues. Returns True
    when the project was synced.
    """
    global global_errors, synced_projects
    project_name = f"{project.get('application_name', '')}/{project.get('name', '')}"
    try:
        desired, ok = fetch_v3_desired(project.get("uuid", ""), floor)
        create_wi_v3(project, desired, custom_flds, wi_type)
        # Kept for continuity: (project id, "Application/Project", the Azure project it was
        # written to). reconcile_after_sync -- no longer called by main(), since closure now
        # runs inline here -- is its only remaining reader.
        synced_projects.append((project.get("uuid", ""), project_name, conf.azure_project))
        reconcile_project(project, floor=floor, desired=desired, ok=ok)
        return True
    except Exception as err:
        global_errors += 1
        logger.error(f"[{ex()}] Sync failed for Mend project {project_name}: {err}. "
                     f"The remaining projects are still synced.")
        return False


def run_sync_routed(projects: list, custom_flds: list, wi_type: str, floor: float):
    """Routed variant: each Mend project's Azure target comes from its own 3.0 tags.

    `projects` are 3.0 project dicts that already survived select_projects, so MEND_*TOKEN
    narrowing has happened and there are no scope-excluded / out-of-scope outcomes left to
    preset -- routing.py only decides no-target / schema-fault / branch-filtered / unknown.
    """
    global exist_wis, global_errors, run_failed
    # conf.azure_project, conf.reponame and conf.azure_area are all re-pointed per target
    # below and must be restored: create_area mutates azure_area cumulatively, and a leaked
    # azure_project would write -- or close -- work items in the wrong Azure project.
    original_azure_project = conf.azure_project
    original_reponame = conf.reponame
    original_azure_area = conf.azure_area
    try:
        known = list_azure_projects()
        if known is None:
            global_errors += 1
            run_failed = True
            return "Aborted: could not list Azure DevOps projects."
        # Azure project names are matched case-insensitively for lookup, but classify()'s
        # known_projects membership test is deliberately exact-string (routing.py stays dumb).
        # Normalise here, the only place that sees both the real Azure names and the raw tag
        # value, by rewriting each route's azure_project to the canonically-cased name before
        # classify() ever runs.
        known_by_casefold = {name.casefold(): name for name in known}

        routes, by_uuid = {}, {}
        for project in projects or []:
            uuid = project.get("uuid", "")
            by_uuid[uuid] = project
            route = parse_route(project.get("tags") or {})
            if route.azure_project:
                route.azure_project = known_by_casefold.get(route.azure_project.casefold(),
                                                            route.azure_project)
            routes[uuid] = route

        targets, outcomes = build_table(routes, known, conf.branches)
        report = coverage_report(outcomes)
        routed = len([o for o in outcomes.values() if o == SKIP_OK])
        # branch-filtered is "the normal state during rollout" per routing.py, so a run made
        # up entirely of deliberate skips must not be fatal. Only outcomes that actually
        # reached a routing decision count.
        considered = [t for t, o in outcomes.items()
                      if o not in (SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_BRANCH)]
        if considered and not routed:
            # Zero coverage among projects that reached a routing decision is never normal,
            # and must be FATAL: logging at ERROR alone still lets main() print "completed
            # successfully" and exit 0.
            global_errors += 1
            run_failed = True
            logger.error(f"{report} - nothing routed. Check MEND_BRANCHES "
                         f"('{conf.branches}') and the scan template's tag keys.")
        elif outcomes and not routed:
            logger.warning(f"{report} - nothing routed this window.")
        else:
            logger.info(report)
        for uuid, outcome in sorted(outcomes.items()):
            if outcome in LOUD_OUTCOMES:
                logger.error(f"Mend project {uuid}: {outcome} "
                             f"(destination '{routes[uuid].azure_project}')")
        unknown = len([o for o in outcomes.values() if o == SKIP_UNKNOWN])
        if unknown and routed and unknown >= routed:
            # Many unknown targets is more likely a PAT that cannot see those projects than
            # that many bad tags. We cannot prove it - call_azure_api collapses 403 and 404.
            logger.error(f"{unknown} destinations were not found in the organization. If they "
                         f"exist, the PAT may lack visibility into them.")

        synced = 0
        for azure_project in sorted(targets):
            # Each Azure project is its own failure boundary: one bad target must not cost the
            # other 106.
            conf.azure_project = azure_project
            conf.azure_area = original_azure_area
            # exist_wis is per AZURE project and MUST be re-read whenever the target changes,
            # or every title is matched against another project's work items - which both
            # duplicates work items and, now that closure is live, closes the wrong ones.
            exist_wis = get_exist_wi()
            if exist_wis is None:
                global_errors += 1
                run_failed = True
                exist_wis = []
                logger.error(f"Skipping Azure project '{azure_project}': could not read "
                             f"existing work items. Nothing is created or closed for the Mend "
                             f"project(s) routed to it; the next run retries them.")
                continue
            for uuid, route in targets[azure_project]:
                conf.reponame = route.repo
                if sync_project_v3(by_uuid[uuid], floor, custom_flds, wi_type):
                    synced += 1
        return f"{report}; {synced} Mend project(s) synced"
    finally:
        conf.azure_project = original_azure_project
        conf.reponame = original_reponame
        conf.azure_area = original_azure_area


def selection_tokens():
    """The configured selection UUIDs -> (include, exclude, {value: the variable it came from}).

    The variable map exists only so an unresolved value can be reported with the name of the
    variable an operator has to go and fix.
    """
    include, exclude, source = [], [], {}
    for raw, var, bucket in ((conf.wsproducttoken, "MEND_PRODUCTTOKEN", include),
                             (conf.wsprojecttoken, "MEND_PROJECTTOKEN", include),
                             (conf.wsexcludetoken, "MEND_EXCLUDETOKEN", exclude)):
        for value in [v.strip() for v in str(raw or "").split(",") if v.strip()]:
            bucket.append(value)
            source.setdefault(value, var)
    return include, exclude, source


def run_sync(st_date: str, end_date: str, custom_flds: list, wi_type: str):
    """Drive the whole run from Mend 3.0: select projects, create/update, then close.

    `st_date` and `end_date` are accepted for signature compatibility and are UNUSED. 3.0
    reports a project's complete current state, so there are no windows, no watermarks and no
    retry queue: a project that fails this run is simply read again in full on the next one.
    """
    global exist_wis, global_errors, run_failed, synced_projects
    run_failed = False
    synced_projects = []
    floor = run_severity_floor()
    logger.info(f"Severity floor: MEND_SEVERITY '{conf.severity}' -> {floor}. The SAME floor "
                f"decides which findings earn a work item and which findings hold one open.")
    logger.info(f"Selection mode: "
                f"{'tag-based routing' if conf.routing.lower() == 'true' else 'token list'}")
    # Logged before routing returns: without it a pipeline log cannot answer "did enrichment
    # run?", and 'off' is reached silently by an unexpanded $(MEND_EPSS) /
    # $(MEND_REACHABILITY) as well as by an explicit false.
    logger.info(f"Enrichment: EPSS and Exploit Code Maturity always render; "
                f"Reachability {'on' if reachability_enabled() else 'off'} (MEND_REACHABILITY)")

    projects, ok = fetch_v3_projects()
    if not ok:
        global_errors += 1
        run_failed = True
        return ("Aborted: could not read the Mend project list. Nothing is created and nothing "
                "is closed - a partial list makes a project we failed to read look exactly "
                "like one whose findings are all gone.")

    include, exclude, source = selection_tokens()
    selected, unresolved = select_projects(projects, include, exclude)
    if unresolved:
        # NEVER sync a partial selection. These variables now take 3.0 UUIDs, so a leftover 1.4
        # token selects nothing, which reads as "no work to do" - and with closure live that
        # reads as "everything was remediated".
        global_errors += 1
        run_failed = True
        for value in unresolved:
            variable = source.get(value, "MEND_PRODUCTTOKEN/MEND_PROJECTTOKEN/MEND_EXCLUDETOKEN")
            logger.error(f"{variable} contains '{value}', which matches no Mend project or "
                         f"application UUID. These variables take Mend 3.0 UUIDs now, not 1.4 "
                         f"tokens.")
        return (f"Aborted: {len(unresolved)} configured UUID(s) matched no Mend project or "
                f"application: {', '.join(unresolved)}. Nothing is created and nothing is "
                f"closed.")

    if conf.routing.lower() == "true":
        return run_sync_routed(selected, custom_flds, wi_type, floor)

    exist_wis = get_exist_wi()
    if exist_wis is None:
        global_errors += 1
        run_failed = True
        exist_wis = []
        return (f"Aborted: could not read existing work items in Azure project "
                f"'{conf.azure_project}'. Skipping to avoid creating duplicates and to avoid "
                f"closing work items we cannot see.")
    synced = 0
    for project in selected:
        if sync_project_v3(project, floor, custom_flds, wi_type):
            synced += 1
    return f"{synced} project(s) processed" if selected else "Nothing to create/update"


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


def org_uuid() -> str:
    """The org identifier for 3.0's org-scoped paths.

    Defaults to MEND_APIKEY: the 1.4 org token and the 3.0 organization UUID are both the org's
    identifier from Mend's Administration screen and are plausibly the same value (spec gate G7,
    unverified against a live org). Defaulting means nobody sets MEND_ORGUUID unless they differ.
    Every 3.0 caller goes through here -- never read conf.org_uuid directly.
    """
    return (conf.org_uuid or conf.ws_org_token or "").strip()


def fetch_v3_projects():
    """Every project in the org, with its routing tags and last scan time. One paged call.

    Replaces getAllProjects, getOrganizationProjectVitals, getOrganizationProjectTags and
    get_prj_list_modified -- all four collapse into this.
    """
    # The spec declares this endpoint POST-only (getProjectSummaries) -- confirmed against
    # references/3.0 (2).json, which lists only "post" under this path. Every other 3.0 endpoint
    # in use is GET; this is the one exception.
    rows, ok = fetch_v3_pages(f"orgs/{org_uuid()}/projects/summaries", method="POST")
    if not ok:
        logger.error(f"[{fn()}] Could not read Mend projects for org {org_uuid()}. "
                     f"Nothing is synced this run -- acting on a partial project list could "
                     f"close work items for projects we simply failed to read.")
    return normalise_projects(rows), ok


def fetch_v3_licenses(project_uuid: str):
    """One project's due-diligence license rows -> ({library_name: [license, ...]}, ok).

    GET /projects/{projectUuid}/dependencies/libraries/licenses, confirmed GET-only against
    references/3.0 (2).json (the path declares only a "get" operation). See
    source3.normalise_licenses for the schema this reads.
    """
    rows, ok = fetch_v3_pages(f"projects/{project_uuid}/dependencies/libraries/licenses")
    if not ok:
        logger.error(f"[{fn()}] Could not read library licenses for project {project_uuid}. "
                     f"Callers must not treat the absence of license data here as \"this "
                     f"library has no licenses\".")
    return normalise_licenses(rows), ok


def fetch_v3_desired(project_uuid: str, floor: float):
    """One project's desired end state: {(kind, library): entry}.

    `ok` is the AND of all three reads and is the closure interlock from spec 6.1 --
    reconciliation closes work items absent from `desired`, so a partial read must never be
    mistaken for a shrunken one. A caller seeing ok=False may still create and update (which
    cannot destroy anything) but must NOT close.

    Keyed by (kind, identity-key) rather than by library: one library can carry both a
    vulnerability and a license work item, and they are separate items with different titles.
    The vulnerability half of that key depends on MEND_DEPENDENCY -- the library name in
    dependency mode, "{cve}|{library}" in per-CVE mode, because that mode makes one work item per
    CVE. conf is read HERE and threaded into normalise_findings as a flag; source3 stays pure.

    Every entry carries "licenses" (a list, [] when the library has none) so downstream
    rendering never has to guard for the key's absence.
    """
    findings, findings_ok = fetch_v3_pages(
        f"projects/{project_uuid}/dependencies/findings/security")
    violations, violations_ok = fetch_v3_pages(
        f"orgs/{org_uuid()}/projects/{project_uuid}/violations")
    licenses, licenses_ok = fetch_v3_licenses(project_uuid)

    vuln_entries, unscored = normalise_findings(findings, floor, per_cve=per_cve_mode())
    lic_entries = normalise_violations(violations)

    if unscored:
        # Spec 5.1 requires this to be an explicit rule, not an accident of a missing key.
        logger.info(f"[{fn()}] {unscored} unscored vulnerability finding(s) in project "
                    f"{project_uuid} were INCLUDED: they cannot be compared to MEND_SEVERITY, "
                    f"and a real finding vanishing because Mend has not scored it yet is the "
                    f"worse failure.")

    desired = {}
    for key, entry in vuln_entries.items():
        # licenses are indexed by LIBRARY, and `key` is not the library in per-CVE mode.
        entry["licenses"] = licenses.get(entry["library"], [])
        desired[("vulnerability", key)] = entry
    for lib, entry in lic_entries.items():
        entry["licenses"] = licenses.get(lib, [])
        desired[("license", lib)] = entry
    return desired, (findings_ok and violations_ok and licenses_ok)


def extract_url(url: str) -> str:
    url_ = url if url.startswith("https://") else f"https://{url}"
    url_ = url_.replace("http://", "")
    pos = url_.find("/", 8)
    return url_[0:pos] if pos > -1 else url_


def mend_api_url() -> str:
    """The 2.0/3.0 API host, derived from MEND_URL's host prefixed with 'api-'.

    `conf.ws_url` (MEND_URL) is the SCA app host; the API host is always derivable from it
    by prefixing the hostname with 'api-' (e.g. saas.mend.io -> api-saas.mend.io), per
    product owner confirmation. Idempotent: a host already carrying the 'api-' prefix is
    left alone. Empty `conf.ws_url` yields "" rather than "https://api-".
    """
    if not conf.ws_url:
        return ""
    normalised = extract_url(conf.ws_url)
    host = normalised[len("https://"):]
    if host.startswith("api-"):
        return normalised
    return f"https://api-{host}"


def normalise_state(raw, default: str) -> str:
    """A work item state name, falling back to `default` for an unset or placeholder value.

    Never returns "": Azure rejects an empty System.State, which would fail every close in the
    run and look like a permissions problem.
    """
    text = str(raw or "").strip()
    if not text or re.match(r"\$\(.+\)$", text):
        return default
    return text


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
        wsexcludetoken=varenvs.get_env("wsexcludetoken").strip(),
        azure_area=varenvs.get_env("wsazurearea").strip(),
        azure_type=varenvs.get_env("wsazuretype", "Task").strip(),
        azure_custom=varenvs.get_env("wscustomfields").strip(),
        utc_delta=0,
        dependency=varenvs.get_env("wsdependency").strip(),
        reponame=varenvs.get_env("wsreponame").strip(),
        description=varenvs.get_env("azuredesc").strip(),
        priority=varenvs.get_env("azurepriority").strip(),
        proxy=varenvs.get_env("proxy").strip(),
        routing=varenvs.get_env("wsrouting").strip(),
        branches=varenvs.get_env("wsbranches").strip(),
        reachability=varenvs.get_env("wsreachability").strip(),
        email=varenvs.get_env("wsemail").strip(),
        org_uuid=varenvs.get_env("wsorguuid").strip(),
        severity=varenvs.get_env("wsseverity").strip(),
        closed_state=varenvs.get_env("wsclosedstate").strip(),
        reopen_state=varenvs.get_env("wsreopenstate").strip(),
    )
    try:
        return conf
    except Exception as err:
        logger.error(f"[{ex()}] Configuration validation failed: {err}")
        exit(-1)
