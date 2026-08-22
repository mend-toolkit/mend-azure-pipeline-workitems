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
from enrichment import (build_alert_index, decorate_policy_violations, format_epss,
                        format_exploit, format_reachability)
from identity import license_title, matches_library
from routing import (parse_route, build_table, classify, coverage_report, LOUD_OUTCOMES,
                     SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_OK, SKIP_UNKNOWN, SKIP_BRANCH)
from syncstate import (TAG_FAILED, TAG_LASTRUN, TAG_PROJECT, TAG_REVSYNC, VERDICT_FAILED,
                       VERDICT_OK, build_selection, clamp, failed_stamp, is_stale,
                       count_parseable_rows, field_for, keep_or_clamp, parse_tag_map,
                       parse_raw_tags, parse_tag_values, selection_floor, superseded, tag_ops,
                       window_start)
from syncstate import _parse as _parse_timestamp
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
mend_v2_session = None
API_VERSION = "1.4"
AGENT_INFO = {"agent": f"{__tool_name__.replace('_', '-')}", "agentVersion": __version__}
DEFAULT_PRIORITY = 2
# The reverse sync selects only these two (see update_wi_for_project's tag clause), so a work
# item created for any other policy match type can never round-trip to Mend. Creating one
# orphans it, and #4 means nothing ever closes it.
SUPPORTED_POLICY_TYPES = ("LICENSE", "VULNERABILITY_SCORE")
uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
token_pattern = r"^[0-9a-zA-Z]{64}$"
azurearea = r"^[0-9a-zA-Z\s\-_]+$"
global_errors = 0
exist_wis = []
synced_projects = []   # [(prj_token, "Product/Project", azure_project)] appended by create_wi
updated_wi = []
# Tracks which library keyId first claimed each exist_id this run, so a second library that
# happens to render the same title (see FINDING 1 in the strict-title review) can be detected
# instead of silently dropped by the `exist_id not in updated_wi` guard below.
wi_claim_keyid = {}
run_failed = False
project_tag_state = None      # one getOrganizationProjectTags sweep per run
project_tag_values = {}       # {token: {field: [every value]}} from that same sweep
project_raw_tags = {}         # {token: {raw tag key: [values]}} from that same sweep, used by
                               # fetch_project_tags for routing (routing tags are not ours)
tag_state_available = True    # False once any tag call fails; drives the once-per-run warning
tag_sweep_ok = True           # False only when the getOrganizationProjectTags sweep ITSELF
                               # failed or was unreadable -- unlike tag_state_available, a later
                               # tag WRITE failure does not flip this. fetch_project_tags gates
                               # on this, not tag_state_available, so one failed saveProjectTag
                               # mid-run does not abort routing for the rest of the run.
TAG_WARNED = False            # WARNING_MSG-style guard so 400 projects log one error, not 400
ALERTS_WARNED = False         # same guard for the enrichment alerts fetch: a user key that
                               # cannot read alerts fails for all ~107 projects identically
product_token_expansion_cache = {}   # {producttoken string: [expanded project tokens]},
                               # memoized so the forward and reverse paths don't each pay
                               # one Mend call per product token in the same run. Only a
                               # SUCCESSFUL expansion is cached -- a failure must stay
                               # failing, never papered over by a stale cache entry.


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
    if conf.epss.lower() not in ("true", "false"):
        res.append(f"MEND_EPSS must be 'true' or 'false', got '{conf.epss}'")
    if conf.reachability.lower() not in ("true", "false"):
        res.append(f"MEND_REACHABILITY must be 'true' or 'false', got '{conf.reachability}'")
    if try_or_error(lambda: int(conf.maxlookback) <= 0, True):
        res.append(f"MEND_MAXLOOKBACK must be a positive number of hours, got '{conf.maxlookback}'")
    if conf.email and not conf.api_url:
        res.append("MEND_APIURL is required when MEND_EMAIL is set (Mend 2.0/3.0 live on the "
                   "API host, not the SCA host)")
    if conf.api_url and not conf.email:
        res.append("MEND_EMAIL is required when MEND_APIURL is set")
    return res


def migration_seed() -> str:
    """Best-effort read of the legacy Azure `Lastrun` property, for one purpose only.

    On the first run after upgrading, no project carries tags yet, so the selection floor would
    fall back to a full window. Seeding it from the old property keeps that upgrade cheap. This
    is the ONLY remaining reference to Azure project properties: it never exits, never sets
    run_failed, and returns "" on any failure. Removable once every deployment has run once.
    """
    # Must consult tag state itself: main() calls this BEFORE run_sync, so the module global is
    # still None at this point and a bare truthiness check would never skip the Azure call.
    # fetch_project_tag_state is memoised, so this is the same one sweep run_sync will reuse.
    if fetch_project_tag_state():
        return ""
    azure_prj_id = try_or_error(lambda: get_azure_prj_id(conf.azure_project), "")
    if not azure_prj_id:
        return ""
    r, errorcode = call_azure_api(api_type="GET", api=f"projects/{azure_prj_id}/properties",
                                  data={}, version="7.0-preview",
                                  cmd_type="?keys=Lastrun&", header="application/json")
    if errorcode != 0:
        logger.info("No legacy Lastrun property available to seed from; using MEND_MAXLOOKBACK.")
        return ""
    return try_or_error(lambda: r["value"][0]["value"], "")


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
        # None, not a short list: create_wi reads rt_res[2:] as findings, so a two-element error
        # return is indistinguishable from a project with no findings — which would advance that
        # project's watermark past a window that was never read.
        logger.error(f"[{ex()}] Process getting Policy issues failed for {prj_token}: {err}")
        return None

    return rt_res


def _warn_tag_state_once(detail: str):
    """One error per run, not one per project. set_lastrun's per-call increment is exactly the
    trap this avoids: 400 identical failures would drown the error count."""
    global TAG_WARNED, tag_state_available, global_errors
    tag_state_available = False
    if TAG_WARNED:
        return
    TAG_WARNED = True
    global_errors += 1
    logger.error(f"[{fn()}] Could not persist sync state as Mend project tags ({detail}). "
                f"Windows fall back to MEND_MAXLOOKBACK and overlapping work is repeated each "
                f"run. Read the response above before assuming a permissions problem: this "
                f"warning used to blame MEND_USERKEY for writes that had in fact succeeded.")


def _tag_call(request_type: str, prj_token: str, key: str, value: str) -> bool:
    body = {"requestType": request_type,
            "userKey": conf.ws_user_key,
            "orgToken": conf.ws_org_token,
            "projectToken": prj_token,
            "tagKey": key,
            "tagValue": value}
    # The call stays inside try_or_error: the original one-liner wrapped json.dumps and
    # call_ws_api as well as the parse, so an exception from either was tolerated. Hoisting
    # only the parse out would turn a survivable transport failure into a dead run.
    raw = try_or_error(lambda: call_ws_api(data=json.dumps(body)), "")
    payload = try_or_error(lambda: json.loads(raw), None)
    logger.debug(f"[{fn()}] {request_type} {key} on {prj_token} -> {str(raw)[:300]}")
    # Success is "no error reported", NOT the presence of a "projectTags" key. Requiring that key
    # (nothing documents it on a write) made every successful save look failed: verified live
    # 2026-08-21, where a save warned here at 14:55:38 and its value -- the run's todate,
    # 2026-08-21 14:55:01 -- was in the org's tags immediately afterwards. Mend 1.4 reports
    # failure in the body, the way get_prj_list_modified already reads it. errorCode 0 is
    # success, so only a truthy code or any errorMessage counts.
    error = ""
    if isinstance(payload, dict):
        error = str(payload.get("errorMessage") or "")
        code = payload.get("errorCode")
        if not error and code not in (None, 0, "0", ""):
            error = f"errorCode {code}"
    if payload is None or error:
        # An empty body cannot be told apart from a rejected write: call_ws_api returns "" for
        # every non-200 and the status code is gone by the time it reaches here. Report it.
        detail = (f"returned {error}" if error else
                  f"returned {str(raw)[:200]}" if str(raw).strip() else
                  "returned an empty body: non-200 or transport failure")
        _warn_tag_state_once(f"{request_type} of '{key}' on {prj_token} {detail}")
        return False
    return True


def save_project_tag(prj_token: str, key: str, value: str) -> bool:
    return _tag_call("saveProjectTag", prj_token, key, value)


def remove_project_tag(prj_token: str, key: str, value: str = "") -> bool:
    # removeProjectTag takes the same tagKey/tagValue pair as save and matches on the VALUE,
    # deleting only that one and leaving any others under the key (verified live 2026-08-21:
    # pruning the superseded azure-wi-lastrun left exactly the current value behind). So callers
    # must pass the value the org sweep actually read back -- "" would name nothing.
    return _tag_call("removeProjectTag", prj_token, key, value)


def replace_project_tag(prj_token: str, key: str, value: str) -> bool:
    """Save one tag value and delete the ones it supersedes.

    saveProjectTag does NOT replace: it adds another value under the same key (verified live
    2026-08-21 in both the API and the Mend UI -- two runs left azure-wi-lastrun carrying two
    timestamps). Nothing removes the old one on its own, so each key would grow by one value per
    run per project, against a tag value limit that is still unverified.

    Save first, prune second, and never prune the value just written. If the prune fails, the key
    keeps both values and parse_tag_map's latest-wins reading is still correct; the reverse order
    would leave a project with no watermark at all whenever the save failed, silently widening its
    next window to MEND_MAXLOOKBACK.
    """
    if not save_project_tag(prj_token, key, value):
        return False
    field = field_for(key)
    if not field:
        return True
    stored = (project_tag_values.get(prj_token) or {}).get(field) or []
    for stale in superseded(stored, value):
        remove_project_tag(prj_token, key, stale)
    # Track what this run wrote, so a second save for the same key prunes the value this run
    # superseded rather than re-issuing a remove for one already gone.
    project_tag_values.setdefault(prj_token, {})[field] = [value]
    return True


def clear_project_tag(prj_token: str, key: str, value: str = ""):
    """Delete every value stored under one key, not just the one the caller named.

    tag_ops names a single TAG_FAILED value (the winner of the read-once map). With append
    semantics a project that failed several runs carries several, and one value left behind keeps
    it in the retry queue forever.
    """
    field = field_for(key)
    stored = list((project_tag_values.get(prj_token) or {}).get(field) or []) if field else []
    for stale in sorted(set(stored + ([value] if value else []))):
        remove_project_tag(prj_token, key, stale)
    if field:
        project_tag_values.setdefault(prj_token, {}).pop(field, None)


def apply_tag_ops(prj_token: str, ops: list):
    """Apply an ordered op list from syncstate.tag_ops, stopping if an advance fails.

    A failed advance must not be followed by clearing TAG_FAILED: that would drop the project
    from the retry queue while its watermark still points at a window we never read.
    """
    for op, key, value in ops or []:
        if op == "save":
            if not replace_project_tag(prj_token, key, value):
                return
        elif op == "remove":
            clear_project_tag(prj_token, key, value)


def record_verdict(prj_token: str, verdict: str, todate: str, state: dict):
    """Persist one project's verdict and make a FAILED one visible in the run.

    create_wi's message is deliberately byte-identical to the pre-change format, so a project
    whose every work item write was rejected still returns a success-shaped "0 ... work items"
    line. Without this the only trace of a wholly failed project is a tag in Mend: main() would
    print "Sync process completed successfully" and exit 0.

    run_failed is deliberately NOT set. One project's failure must not withhold every other
    project's state — that all-or-nothing withhold is exactly what this design removed.
    """
    global global_errors
    if verdict == VERDICT_FAILED:
        global_errors += 1
        logger.error(f"[{fn()}] Mend project {prj_token} did not sync completely. Its sync state "
                    f"is not advanced and it will be retried on the next run.")
    apply_tag_ops(prj_token, tag_ops(verdict, todate, failed_stamp(prj_token, state)))


def save_project_addr(prj_token: str, state: dict):
    """Persist TAG_PROJECT for one Mend project, but only when the value differs from what
    the read-once tag map already holds -- zero writes in steady state.

    Sourced from `synced_projects` (populated unconditionally by create_wi, regardless of
    verdict) rather than recomputed, so the stored address always matches the exact tag
    string create_wi wrote onto the work items themselves. A project create_wi never reached
    this run (job timeout, exception outside its try) has no synced_projects entry, so this
    is a no-op for it -- there is nothing yet to address, and the previously stored address
    (if any) is left untouched.

    On a successful write, also updates `state` in place. `state` is the same dict object
    fetch_project_tag_state() memoises as `project_tag_state`, so this lets the same run's
    update_wi_in_thread (which reads that same memoised map) see the address a project was
    just given, instead of the reverse sync skipping it until the following run. It also
    means a token addressed twice in the same run short-circuits on the second call via the
    "already differs" check above, rather than re-writing.
    """
    project_tag = next((tag for token, tag, _ in synced_projects if token == prj_token), "")
    if not project_tag:
        return
    desired = f"{conf.azure_project}|{project_tag}"
    if (state.get(prj_token) or {}).get("project") == desired:
        return
    if replace_project_tag(prj_token, TAG_PROJECT, desired):
        state.setdefault(prj_token, {})["project"] = desired


def project_window(prj_token: str, state: dict, todate: str, max_hours, reset_on: bool) -> str:
    """window_start, plus the warning a stale watermark owes the operator.

    A stored watermark is used as stored however old (syncstate.keep_or_clamp): flooring it
    would skip everything between it and the floor, and the next OK verdict would close that
    gap for good. The price is a window wider than MEND_MAXLOOKBACK, which must not be silent.
    """
    start = window_start(prj_token, state, todate, max_hours, reset_on, reset_back_time)
    if not reset_on and is_stale((state or {}).get(prj_token, {}).get("lastrun"),
                                 todate, max_hours):
        logger.warning(f"[{fn()}] Mend project {prj_token} last synced {start}, which is older "
                      f"than MEND_MAXLOOKBACK ({max_hours}h), so its window is wider than that "
                      f"limit. Narrowing it would permanently discard everything raised in "
                      f"between. Expect extra idempotent work until it succeeds once.")
    return start


def fetch_project_tag_state() -> dict:
    """{token: {lastrun, failed, revsync}} for the whole org, read once per run.

    Memoised for the run -- one sweep answers every caller. An unreadable sweep returns {} and marks state
    unavailable rather than raising: every window then falls back to the clamp, which is correct
    but repeats work, so the operator needs the warning and the run needs to continue.

    Also sets tag_sweep_ok = False on either of its own two failure paths (unreadable body;
    rows present but structurally unparseable). fetch_project_tags gates on that flag, so this
    is a genuinely new behaviour versus the pre-Task-4 code: previously a structurally-bad sweep
    only warned and let every window fall back to the per-project clamp, with routing untouched
    (routing read the separate 2.0 /entities call). Now project_raw_tags -- the routing tags --
    comes from this same sweep, so the same failure also aborts a routed run outright rather
    than silently routing nothing. Deliberate: failing loudly beats routing nothing silently.
    """
    global project_tag_state, project_tag_values, project_raw_tags, tag_sweep_ok
    if project_tag_state is not None:
        return project_tag_state
    body = {"requestType": "getOrganizationProjectTags",
            "userKey": conf.ws_user_key,
            "orgToken": conf.ws_org_token}
    payload = try_or_error(lambda: json.loads(call_ws_api(data=json.dumps(body))), None)
    rows = try_or_error(lambda: payload["projectTags"], None)
    if rows is None:
        _warn_tag_state_once("getOrganizationProjectTags")
        tag_sweep_ok = False
        project_tag_state = {}
        return project_tag_state
    # All three views come from the one sweep: the winners the run reads, every value (which is
    # what replace_project_tag has to name to delete a superseded one), and the raw per-token tag
    # dict routing reads (see fetch_project_tags) -- routing tags are not ours, so they are not
    # in project_tag_values/parse_tag_map's four-key contract.
    project_tag_values = parse_tag_values(rows)
    project_raw_tags = parse_raw_tags(rows)
    project_tag_state = parse_tag_map(rows)
    if rows and not count_parseable_rows(rows):
        # Rows the parser cannot structurally read means the row shape is not what parse_tag_map
        # expects. Without this the run logs "Sync state: Mend project tags", every window
        # silently falls to the clamp, no project is ever retried, and migration_seed re-reads
        # the frozen legacy property forever. Deliberately no guessing at alternative key names:
        # this exists to make a mismatch loud, not to paper over it.
        #
        # The test is structural, NOT "did any project yield state". Most projects in an org
        # carry only CLI scan tags (CTX, commitId, repoFullName) and none of ours, so on the
        # first run after upgrade every row parses to nothing — normal, and it used to spend
        # this run's one warning on a mismatch that did not exist.
        _warn_tag_state_once("getOrganizationProjectTags returned rows in an unexpected shape")
        tag_sweep_ok = False
    return project_tag_state


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


def fetch_project_tags(tokens: list) -> dict:
    """Map Mend 1.4 project token -> that project's tags, from the org sweep.

    Returns None (the whole call) if the sweep was unreadable OR structurally unparseable
    (fetch_project_tag_state's tag_sweep_ok), matching the previous all-or-nothing convention:
    a partial map would make a real project look untagged and route nothing, silently. The
    structurally-unparseable case is new: it used to only cost sync state its watermark and let
    routing continue via the separate 2.0 /entities call; now routing tags come from the same
    sweep, so the same bad shape means no routing tags exist for anyone and the whole call fails
    rather than quietly routing nothing.

    This used to join 2.0 /entities rows to 1.4 tokens on (productName, projectName), because
    1.4 tokens and 2.0 uuids are different identifier spaces. The 1.4 sweep carries the same
    routing tags keyed by the token directly (verified live 2026-08-21), which removes the
    join, the getAllProducts/getAllProjects fan-out behind it, and the duplicate-name-pair
    ambiguity that forced SKIP_UNKNOWN for two projects sharing a name pair. Per-token None
    (the collision signal) is gone with it: tokens cannot collide, so an unresolved token is
    simply untagged ({}), same as a resolved-but-tagless one.
    """
    fetch_project_tag_state()
    if not tag_sweep_ok:
        return None
    return {token: dict(project_raw_tags.get(token) or {}) for token in tokens}


def epss_enabled() -> bool:
    return conf.epss.lower() == "true"


def reachability_enabled() -> bool:
    return conf.reachability.lower() == "true"


def alerts_enabled() -> bool:
    # Both signals arrive in the same getProjectAlertsByType response, so turning either
    # (or both) on costs exactly one alerts call per project -- the same as one.
    #
    # No enrichment_disabled latch any more: it existed because a persistent 3.0 401/403 meant
    # the org lacked a 3.0 entitlement, which no amount of retrying would fix. Alerts ride the
    # same 1.4 transport and credential as every other call, so a failure there is not an
    # enrichment-specific condition to latch on.
    return epss_enabled() or reachability_enabled()


def requested_signal_names() -> str:
    """Human-readable list of the enrichment signals actually requested this run, for the
    once-per-run alerts-fetch-failed warning. Naming only what was asked for keeps the
    message honest when an org only has one of the two flags turned on."""
    signals = []
    if epss_enabled():
        signals.extend(["EPSS", "Exploit Code Maturity"])
    if reachability_enabled():
        signals.append("Reachability")
    if len(signals) <= 1:
        return "".join(signals)
    if len(signals) == 2:
        return " and ".join(signals)
    return f"{', '.join(signals[:-1])}, and {signals[-1]}"


def enrich_project(prj_token: str) -> dict:
    """Enrichment index for one Mend project, or {} if unavailable for any reason."""
    if not alerts_enabled():
        return {}
    return try_or_error(lambda: fetch_project_alerts(prj_token), {})


def safe_decorate(sorted_libs: list, index: dict):
    """Decorate this project's issue objects, absorbing anything that goes wrong.

    create_wi has one outer try whose error string both callers log at INFO, so an
    exception raised here would silently drop every Work Item for the project while the run
    still reported success. Display-only data must never cost a Work Item. The whole body
    runs inside one try_or_error, not just the decorate_policy_violations call: an arity
    change in its return value must not raise into create_wi either.
    """
    def _decorate():
        candidates, matched = decorate_policy_violations(sorted_libs, index)
        if candidates and not matched:
            # The alerts index carries every open alert in the project, while candidates is
            # only this window's policy violations, so compare against the policy candidates.
            # Comparing against the full alerts total would fire on most projects and train
            # operators to ignore it.
            logger.warning(f"[{fn()}] Enrichment matched 0 of {candidates} candidate finding(s) "
                           f"for this project. If this repeats, the (CVE, library uuid) join key "
                           f"is wrong and every work item will show blank reachability.")

    try_or_error(_decorate, None)
    return None


def epss_exploit_row_fields(policy_el: dict, epss_on: bool) -> dict:
    """The EPSS/Exploit row keys, gated on MEND_EPSS alone -- independent of reachability,
    since an org may not have reachability analysis enabled at all."""
    return {"EPSS": format_epss(policy_el), "Exploit": format_exploit(policy_el)} if epss_on else {}


def reachability_row_field(policy_el: dict, reachability_on: bool) -> dict:
    """The Reachability row key, gated on MEND_REACHABILITY alone."""
    return {"Reachability": format_reachability(policy_el)} if reachability_on else {}


def build_enrich_html(policy_el: dict, epss_on: bool, reachability_on: bool) -> str:
    """The enrichment lines spliced into a CVE's description, gated per flag so each of the
    four flag combinations renders only its own lines. Used by both MEND_DEPENDENCY branches
    -- they are the same feature in two code paths and must behave identically."""
    html = ""
    if reachability_on:
        html += f"<br><b>Reachability:</b> {format_reachability(policy_el)}"
    if epss_on:
        html += f"<br><b>EPSS:</b> {format_epss(policy_el)}" \
                f"<br><b>Exploit Code Maturity:</b> {format_exploit(policy_el)}"
    return html


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


def fetch_project_alerts(prj_token: str) -> dict:
    """{(cve, library keyUuid): values} for one Mend project, from the 1.4 alerts API.

    Replaces the 3.0 findings endpoint. Three things went away with it: the 2.0 login, the
    project-uuid resolution (an alert carries its own 1.4 projectToken), and the paging loop --
    API 1.4 does not paginate.

    Returns {} on any failure rather than raising: this is display-only data and must never
    cost a Work Item. orgToken is omitted to match get_ingnored_alerts, the alerts call this
    tool has been making successfully since before this change.

    An unreadable response warns ONCE per run. Returning {} silently would be invisible:
    create_wi only calls safe_decorate when the index is non-empty, and safe_decorate owns the
    only other enrichment warning ("matched 0 of N candidate finding(s)"), so a WHOLESALE
    failure -- the exact case where the operator most needs to know -- would skip both and
    render "-" in every column with nothing in the log. This restores the single run-level
    warning that the deleted prepare_enrichment used to emit.
    """
    global ALERTS_WARNED
    body = {"requestType": "getProjectAlertsByType",
            "userKey": conf.ws_user_key,
            "projectToken": prj_token,
            "alertType": "SECURITY_VULNERABILITY"}
    payload = try_or_error(lambda: json.loads(call_ws_api(data=json.dumps(body))), None)
    alerts = try_or_error(lambda: payload["alerts"], None)
    if not isinstance(alerts, list):
        if not ALERTS_WARNED:
            # Once per run, not once per project: one bad credential or entitlement fails
            # identically for all ~107 projects and would otherwise log 107 times.
            ALERTS_WARNED = True
            logger.warning(f"[{fn()}] Could not read Mend alerts for enrichment "
                           f"(getProjectAlertsByType on {prj_token} returned {payload}). "
                           f"{requested_signal_names()} will be blank ('-') on every work "
                           f"item this run. Enrichment is display-only, so the run continues "
                           f"and no work item is lost.")
        return {}
    return build_alert_index(alerts)


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


def call_ws_api_v3(api: str, params: dict = None):
    # Same (payload, errorcode) convention as call_ws_api_v2. Mend 3.0 accepts the JWT
    # minted by the 2.0 login, so there is deliberately no separate 3.0 login path — but
    # 3.0 lives on the same API host as 2.0, not on the 1.4 SCA app host.
    global mend_v2_session
    url = f"{extract_url(conf.api_url)}/api/v3.0/{api}"
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


def fetch_v3_pages(api: str, params: dict = None, limit: int = 1000):
    """Walk every cursor page of a 3.0 collection endpoint.

    Returns (items, ok). `ok` is False if ANY page failed, was malformed, the page cap was hit, a
    cursor repeated, or the collected count disagrees with the server's totalItems -- and it is
    load-bearing: reconciliation closes work items that are absent from a fetch, so a caller MUST
    treat ok=False as "I know nothing about this project" rather than as a shorter list. Returning
    the partial items alongside ok=False is deliberate: they are useful for creating and updating,
    which cannot do harm, while closure must be skipped entirely.
    """
    items = []
    cursor = None
    seen_cursors = set()
    for _ in range(MAX_V3_PAGES):
        page_params = dict(params or {})
        page_params["limit"] = limit
        if cursor is not None:
            page_params["cursor"] = cursor
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


def check_wi_id_matching(title_matches, project_name: str):
    """Find a live work item whose title satisfies `title_matches` and which carries
    `project_name` as a tag. Returns its id, or 0.

    `title_matches` is a predicate over the title so callers can match either an exact title or
    a legacy title shape (see identity.py) through one code path -- the tag-ownership rule below
    is the part that must not be duplicated.
    """
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


def clamp_revsync(prj_token, state, todate, max_hours, reset_on):
    """window_start reads TAG_LASTRUN; the reverse direction needs TAG_REVSYNC.

    Same rule as project_window: a stored watermark is honoured however old, because narrowing
    it would drop the work item changes in between and the next success would write over them.

    An absent (or unparseable) watermark is the "first-ever reverse sync" case and must not be
    floored at MEND_MAXLOOKBACK -- that would silently start only 30 days back. It looks back
    reset_back_time instead, once per project.
    """
    if reset_on:
        return clamp(None, todate, reset_back_time)
    stored = (state.get(prj_token) or {}).get("revsync")
    if _parse_timestamp(stored) is None:
        return clamp(None, todate, reset_back_time)
    if is_stale(stored, todate, max_hours):
        logger.warning(f"[{fn()}] Mend project {prj_token} last pushed work item state "
                      f"{stored}, older than MEND_MAXLOOKBACK ({max_hours}h). Its reverse "
                      f"window stays that wide rather than skipping the gap.")
    return keep_or_clamp(stored, todate, max_hours)


def update_wi_for_project(prj_token: str, project_tag: str, todate: str):
    global conf, global_errors, run_failed
    if conf is None:
        conf = startup()
        conf.update_properties()
    state = fetch_project_tag_state()
    reset_on = conf.reset.lower() == "true"
    max_hours = try_or_error(lambda: int(conf.maxlookback), 720)
    # Scoped to one Mend project so its watermark can live on that project as a tag. The extra
    # tag clause also shrinks every result set, which relieves the 20,000-row WIQL cap (#5).
    since = clamp_revsync(prj_token, state, todate, max_hours, reset_on)
    try:
        logger.info(f"Start to update Mend's data for {project_tag}")
        first_id = 0
        executed_wi = 0
        project_failed = False
        tag_lic = Tags.get_el_by_name("LICENSE")
        tag_vul = Tags.get_el_by_name("VULNERABILITY_SCORE")
        while True:
            data = {"query": f'select [System.Id] From WorkItems Where '
                             f'[System.ChangedDate] > "{since}" And '
                             f'[System.TeamProject] = "{conf.azure_project}" And [System.Id] > {first_id} '
                             f'AND ([System.Tags] CONTAINS "{project_tag}") '
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
                project_failed = True
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
                    project_failed = True
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
                                wi_prj_token = ""
                                for wq_el_rel_ in wq_el['relations']:
                                    if wq_el_rel_['rel'] == "Hyperlink":
                                        wi_prj_token = try_or_error(lambda: wq_el_rel_['attributes']['comment'].split(",")[0], "")
                                        uuid = try_or_error(lambda: wq_el_rel_['attributes']['comment'].split(",")[1], "")

                                wq_el_url = wq_el['url'][0:wq_el['url'].find("apis")] + f"workitems/edit/{issue_id}"
                                ext_issues = [{"identifier": f"{issue_wi_title}",
                                               "url": wq_el_url,
                                               "status": wq_el['fields']['System.State'],
                                               "lastModified": wq_el['fields']['System.ChangedDate'],
                                               "created": wq_el['fields']['System.CreatedDate']
                                               }]
                                try:
                                    if uuid and wi_prj_token:
                                        data = json.dumps(
                                            {"requestType": "updateExternalIntegrationIssues",
                                             "userKey": conf.ws_user_key,
                                             "orgToken": conf.ws_org_token,
                                             "projectToken": wi_prj_token,
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
        if not project_failed:
            replace_project_tag(prj_token, TAG_REVSYNC, todate)
            return f"Updated {executed_wi} work item(s) for {project_tag}"
        # Same string on both paths made a project whose WIQL blew up indistinguishable from
        # an empty success in the joined summary line.
        return (f"Updated {executed_wi} work item(s) for {project_tag} before failing; "
                f"its reverse sync state was not advanced and will be retried")
    except Exception as err:
        global_errors += 1
        run_failed = True
        return f"[{ex()}] Update Mend's data failed: {err}"


def reverse_targets(state: dict) -> list:
    """[(token, azure_project, project_tag)] for every project the tag map has an address for.

    Deliberately independent of this run's forward outcome (spec 5.6.1): a dormant or archived
    repo's closed work items must still reach Mend, so this walks the whole read-once tag map
    rather than `synced_projects` (which only supplies the address create_wi resolves this run,
    for save_project_addr to persist).

    A malformed or half-empty stored value -- an empty Azure project, an empty tag half, or a
    tag half that would make the WIQL "CONTAINS" clause match every project (a leading or
    trailing "/") -- is skipped and logged, never guessed at nor defaulted to conf.azure_project:
    guessing here risks pushing an unrelated work item's state to the wrong Mend project. Both
    halves are stripped before validation, so a whitespace-padded half neither slips a padded
    (non-matching) value into the WIQL clause nor a whitespace-only half past the emptiness check.
    """
    out = []
    for token, entry in sorted((state or {}).items()):
        stored = (entry or {}).get("project") or ""
        if not stored:
            continue
        azure_project, _, project_tag = stored.partition("|")
        azure_project, project_tag = azure_project.strip(), project_tag.strip()
        if not azure_project or not project_tag or project_tag.startswith("/") \
                or project_tag.endswith("/"):
            logger.error(f"[{fn()}] Skipping reverse sync for {token}: malformed "
                         f"{TAG_PROJECT} value '{stored}'.")
            continue
        out.append((token, azure_project, project_tag))
    return out


def update_wi_in_thread():
    # Kept under the original name because azure_wi_sync.py imports it by that name.
    # Visits every Mend project the tag map has an address for, every run -- not this run's
    # forward outcome, and not get_prj_list_modified. That is what closes the regression
    # against pre-branch behaviour: a quiet/dormant repo whose work items get closed must
    # still be pushed back to Mend even though nothing about it changed on the forward side.
    global conf, global_errors, run_failed
    if conf is None:
        conf = startup()
        conf.update_properties()
    targets = reverse_targets(fetch_project_tag_state())
    if not targets:
        return "No Mend project has a stored reverse-sync address; reverse sync skipped."

    # Mirror run_sync_routed's scope narrowing (core.py, expand_product_tokens caller)
    # exactly, so a run scoped to one product/project does not pay a WIQL query plus a
    # work-item hydration for every project the org has ever tagged. Absent config narrows
    # nothing (spec 5.6.1's dormant-repo guarantee).
    scope = set()
    if conf.wsproducttoken:
        expanded = expand_product_tokens(conf.wsproducttoken)
        if expanded is None:
            # Failing to expand must never widen scope -- silently visiting every tagged
            # project would be the exact bug this filtering exists to fix.
            global_errors += 1
            run_failed = True
            return "Aborted: could not expand MEND_PRODUCTTOKEN; refusing to widen reverse sync scope."
        scope.update(expanded)
    if conf.wsprojecttoken:
        scope.update(conf.wsprojecttoken.split(","))
    if scope:
        targets = [t for t in targets if t[0] in scope]
    excluded = set(t for t in conf.wsexcludetoken.split(",") if t)
    if excluded:
        targets = [t for t in targets if t[0] not in excluded]
    if conf.routing.lower() == "true":
        # Under routing the token lists are not the selector -- the routing tags are -- so the
        # narrowing above filters nothing in a routed run. A stored address says where a
        # project's work items LIVE; its routing tags say whether the project is still ours to
        # sync. Without this, enabling routing on an org where one project carries tags still
        # cost a WIQL query plus a work-item hydration for every project that had ever been
        # addressed, including ones whose tags were removed runs ago.
        #
        # classify() is reused rather than reimplemented so this cannot drift from the forward
        # side's definition of routable. The stored Azure project is passed as the known-projects
        # set so its destination check passes trivially: the reverse sync visits the address the
        # work items were actually written to, which is not necessarily where the routing tags
        # point today, and re-deriving that here would send state to the wrong project.
        routable = {token for token, azure_project, _ in targets
                    if classify(parse_route((project_raw_tags or {}).get(token) or {}),
                                {azure_project}, conf.branches) == SKIP_OK}
        addressed = len(targets)
        targets = [t for t in targets if t[0] in routable]
        if len(targets) != addressed:
            # Deliberately a count, not a token list: an org where routing covers a handful of
            # projects would otherwise print most of its project tokens on every single run.
            logger.info(f"Reverse sync filtered to match the project filter: "
                        f"{len(targets)} of {addressed} project(s) with a stored address.")
    if not targets:
        return "No Mend project in scope has a stored reverse-sync address; reverse sync skipped."

    original_azure_project = conf.azure_project
    todate = (datetime.datetime.now() +
              datetime.timedelta(hours=conf.utc_delta)).strftime("%Y-%m-%d %H:%M:%S")
    results = []
    for prj_token, azure_project, project_tag in targets:
        conf.azure_project = azure_project
        results.append(f"{project_tag}: {update_wi_for_project(prj_token, project_tag, todate)}")
    conf.azure_project = original_azure_project
    return "; ".join(results)


def build_wi_tags(project_tag: str, policy_tag: str, routing: str, reponame: str) -> list:
    # Repo identity is a work item tag because the client declined Area Path. Taking the
    # values as arguments keeps this testable without constructing a whole Config.
    tags = [project_tag, policy_tag]
    if routing.lower() == "true" and reponame:
        tags.append(reponame)
    return tags


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
        nonlocal item_failed
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
                if errcode == 0:
                    # FINDING 2: a PATCH here can rename the item (legacy-title migration, or any
                    # other title change), and exist_wis is read again later this same run
                    # (check_wi_id_matching). Replace the stale cache entry so it reflects the new
                    # title instead of leaving the id cached under the old one too.
                    try:
                        for d in exist_wis:
                            if exist_id in try_or_error(lambda d=d: list(d.values())[0], {}):
                                exist_wis.remove(d)
                                break
                        exist_wis.append({vul_title: {exist_id: ",".join(tags)}})
                    except Exception as err:
                        pass
            try:
                claimed_id = exist_id if exist_id > 0 else r["id"]
                updated_wi.append(claimed_id)
                # FINDING 1: record which library keyId claimed this work item id. exist_id is
                # 0 for a brand-new item until the POST above returns its real id, so this must
                # happen here (after the real id is known) rather than where exist_id was first
                # resolved -- keying on exist_id there would key every new item under 0.
                wi_claim_keyid[claimed_id] = (lib_key_id, lib_name)
            except Exception as err:
                pass

            if errcode == 0:
                count_item += 1
                logger.info(f"{conf.azure_type} {r['id']} {status_op}")
            elif errcode == 1:
                item_failed = True
                logger.warning(f"{conf.azure_type} creation/update failed: {r['message']}")
            else:
                item_failed = True
                info_el = r.pop()
                logger.error(f"[{fn()}] {info_el}")
        except Exception as err:
            item_failed = True
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

    global conf, global_errors, exist_wis, updated_wi, wi_claim_keyid, count_item, synced_projects
    try:
        item_failed = False
        ws_prj = fetch_prj_policy(prj_token, sdate, edate)
        if ws_prj is None:
            # Absence of findings is a real answer; a failed fetch is not. Verdicting OK here
            # would close this project's window having never read it.
            return VERDICT_FAILED, (f"Mend policy fetch failed for project {prj_token}; "
                                    f"nothing synced and its window stays open")
        ignore_alerts = get_ingnored_alerts(project=prj_token) if conf.wsalert.lower() == "false" else []
        prj_lib_hierarchy = try_or_error(lambda: get_prj_lib_hierarchy()["libraries"], [])
        prj_licenses = try_or_error(lambda: get_prj_licenses(), [])
        prj_lib_locations = try_or_error(lambda: get_lib_locations(), [])
        epss_on = epss_enabled()
        reachability_on = reachability_enabled()
        prd_name = ws_prj[0]
        prj_name = ws_prj[1]
        status_op = "created"
        count_item = 0
        skipped_types = {}
        sorted_libs = sorted(ws_prj[2:], key=lambda x: (x["library"]["keyId"], -len(x["policyViolations"])))
        enrichment_index = enrich_project(prj_token) if sorted_libs else {}
        if enrichment_index:
            safe_decorate(sorted_libs, enrichment_index)
        for prj_el in sorted_libs:
            policy_type = try_or_error(lambda: prj_el["policy"]["policyMatch"]["type"], "")
            if policy_type not in SUPPORTED_POLICY_TYPES:
                skipped_types[policy_type or "unknown"] = skipped_types.get(policy_type or "unknown", 0) + 1
                continue
            lib_url = prj_el["library"]["url"]
            lib_name = prj_el["library"]["filename"]
            lib_key_id = try_or_error(lambda: prj_el["library"]["keyId"], "")
            policy_lic_name = try_or_error(
                lambda: prj_el['policy']['name'][prj_el['policy']['name'].find("]") + 1:].strip(), "")
            tags = build_wi_tags(f"{prd_name}/{prj_name}",
                                 Tags.get_el_by_name(policy_type),
                                 conf.routing, conf.reponame)
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
                vul_title = license_title(lib_name) if is_license else f"{lib_name}: " \
                                        f"{len(relevant_vuls)} vulnerabilities (highest severity is {max_severity})"
                hierarchy_libs = ""
                vulnerability_data = ""
                # Vulnerabilities are matched on the library name alone: the count and the highest
                # severity in the title both move when a vulnerability is suppressed, rescored or
                # fixed, and matching on them missed the item, created a duplicate and stranded the
                # original open. Licenses match exactly -- their title has no moving parts.
                if is_license:
                    exist_id = check_wi_id(id=vul_title, project_name=f"{prd_name}/{prj_name}")
                else:
                    exist_id = check_wi_id_matching(
                        lambda t: matches_library(t, lib_name),
                        project_name=f"{prd_name}/{prj_name}")
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
                                # MEND_EPSS and MEND_REACHABILITY both default to false, and
                                # the README/design doc promise a byte-identical work item
                                # when both are off, so these keys are gated per flag. URL
                                # must stay the last key written in every combination:
                                # create_html_table drops the final cell by position, so
                                # anything after URL vanishes.
                                row = {
                                    "CVE": vul_name,
                                    "Severity": vul_severity,
                                    "CVSS": vul_score,
                                }
                                row.update(epss_exploit_row_fields(policy_el, epss_on))
                                row["Dependency"] = lib_name
                                row["Type"] = lib_dep
                                row["Fixed in"] = vul_fix_resolution
                                row.update(reachability_row_field(policy_el, reachability_on))
                                row["URL"] = vul_url
                                table_data.append(row)
                                lic_data = "<br>"
                                for lic_data_ in lic_data_arr:
                                    lic_data = lic_data + f"<a href='{lic_data_[2]}'>{lic_data_[1]}</a>" + \
                                               f"<br><b>License Reference File: </b><a href='{lic_data_[0]}'>{lic_data_[0]}</a><br>" \
                                               f"<b>License Policy Violation - </b>{policy_lic_name}<br>"
                                lic_data = generate_expandable_section("<b>License Details</b>", lic_data) if is_license else ""

                                # MEND_EPSS and MEND_REACHABILITY both default to false, and
                                # the README/design doc promise a byte-identical work item
                                # when both are off.
                                enrich_html = build_enrich_html(policy_el, epss_on, reachability_on)
                                vul_data = "<b>Vulnerable Library:</b>" + lib_name + \
                                    "<br><b>Path to dependency file: </b>" + path_dep + "<br><b>Path to library:</b>" + path_lib + \
                                    "<br><b>Vulnerability Details:</b> " + vul_desc + "<br><b>Publish Date:</b> " + \
                                    vul_publish_date + \
                                    f"<br><b>URL:</b> <a href='{vul_url}'>{vul_name}</a>" + \
                                    "<br><b>CVSS 3 Score Details </b>(" + str(vul_score) + ")" + \
                                    enrich_html + \
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
                    # FINDING 1: two distinct libraries sharing a title (e.g. same filename,
                    # different keyId -- a real Maven/npm case) resolve to the same exist_id.
                    # The guard above already skips the second library's violations; make that
                    # skip visible instead of silent.
                    claimant_key, claimant_name = wi_claim_keyid.get(exist_id, (lib_key_id, lib_name))
                    if claimant_key != lib_key_id:
                        logger.warning(
                            f"[{fn()}] Work item {exist_id} for title '{vul_title}' was already "
                            f"claimed by library '{claimant_name}' (keyId={claimant_key}); "
                            f"library '{lib_name}' (keyId={lib_key_id}) shares the same title and "
                            f"its violations were skipped.")
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

                            exist_id = check_wi_id(id=vul_title, project_name=f"{prd_name}/{prj_name}")
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
                                # MEND_EPSS and MEND_REACHABILITY both default to false, and
                                # the README/design doc promise a byte-identical work item
                                # when both are off.
                                enrich_html = build_enrich_html(policy_el, epss_on, reachability_on)
                                vul_data = "" if is_license else \
                                    "<br><b>Vulnerability Details:</b> " + vul_desc + \
                                    "<br><b>Publish Date:</b> " + vul_publish_date + \
                                    f"<br><b>URL:</b> <a href='{vul_url}'>{vul_name}</a>" + \
                                    "<br><b>CVSS 3 Score Details </b>(" + str(vul_score) + ")" + \
                                    enrich_html + \
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
                            else:
                                # FINDING 1: same exposure as the dependency-mode branch above --
                                # two distinct libraries (e.g. same filename, different keyId) can
                                # render the same per-CVE title and silently collide on exist_id.
                                claimant_key, claimant_name = wi_claim_keyid.get(exist_id, (lib_key_id, lib_name))
                                if claimant_key != lib_key_id:
                                    logger.warning(
                                        f"[{fn()}] Work item {exist_id} for title '{vul_title}' was "
                                        f"already claimed by library '{claimant_name}' "
                                        f"(keyId={claimant_key}); library '{lib_name}' "
                                        f"(keyId={lib_key_id}) shares the same title and its "
                                        f"violations were skipped.")

        if skipped_types:
            detail = ", ".join(f"{name} x{count}" for name, count in sorted(skipped_types.items()))
            logger.info(f"Skipped {sum(skipped_types.values())} violation(s) with unsupported "
                        f"policy type(s) for Mend project '{prj_name}': {detail}. Only "
                        f"{' and '.join(SUPPORTED_POLICY_TYPES)} produce work items.")

        message = f"{count_item} {conf.azure_type} work items created/updated for Mend project " \
                  f"'{prj_name}' (Product '{prd_name}')" if count_item > 0 else \
            f"No {conf.azure_type} work items {status_op} for Mend project '{prj_name}' (Product '{prd_name}')"
        # Written unconditionally: a forward work-item write failure says nothing about
        # whether this project's existing work items changed state (spec 5.6.1). Only
        # create_wi resolves the (product, project) tag string the reverse sync needs; the
        # reverse sync's own project_failed flag still withholds its watermark on a reverse
        # failure.
        synced_projects.append((prj_token, f"{prd_name}/{prj_name}", conf.azure_project))
        return (VERDICT_FAILED if item_failed else VERDICT_OK), message
    except Exception as err:
        return VERDICT_FAILED, f"[{ex()}] Work item creation failed: {err}"


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


def expand_product_tokens(producttoken: str) -> list:
    # Shared by the legacy and routed paths. Two deliberate behaviour changes from the
    # inline block this replaces:
    #   1. No exit(-1) on failure — under routing, one bad product token must not kill
    #      every other target in the run.
    #   2. json.loads(call_ws_api(...)) is now inside the try. In the original it sat
    #      outside, so a non-200 from Mend returned "" and raised an uncaught
    #      JSONDecodeError instead of the graceful failure this refactor exists to give.
    global product_token_expansion_cache
    if producttoken in product_token_expansion_cache:
        return product_token_expansion_cache[producttoken]
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
            # A failure must never be memoized -- caching it would paper over a transient
            # Mend outage as a permanent empty scope.
            return None
    product_token_expansion_cache[producttoken] = res
    return res


def run_sync_routed(modified_projects: list, end_date: str, custom_flds: list,
                    wi_type: str, retry_only=None):
    global exist_wis, global_errors, run_failed
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

    # A token the tag map does not answer for is NOT the same thing as an untagged project.
    # fetch_project_tags returns a dict for every token it is asked about, so this is
    # defensive rather than reachable today (the old reachable cause -- an ambiguous
    # (productName, projectName) join against 2.0 /entities -- is gone with that transport).
    # It stays because a future caller passing a subset of tokens would otherwise get
    # parse_route({}) and land in the QUIET no-target bucket, indistinguishable from a
    # genuinely tagless project. Answer-less means loud: SKIP_UNKNOWN, in LOUD_OUTCOMES.
    unanswered = set()
    routes = {}
    for token in modified_projects:
        per_token_tags = tags.get(token)
        if per_token_tags is None:
            unanswered.add(token)
            per_token_tags = []
        route = parse_route(per_token_tags)
        if route.azure_project:
            route.azure_project = known_by_casefold.get(route.azure_project.casefold(),
                                                         route.azure_project)
        routes[token] = route
    for token in unanswered:
        preset.setdefault(token, SKIP_UNKNOWN)

    targets, outcomes = build_table(routes, known, conf.branches, preset=preset)

    report = coverage_report(outcomes)
    routed = len([o for o in outcomes.values() if o == SKIP_OK])
    # scope-excluded, out-of-scope and branch-filtered are deliberate outcomes — the last
    # is "the normal state during rollout" per routing.py — so a run made up entirely of
    # those must not be fatal. Only count outcomes that actually reached a routing decision.
    considered = [t for t, o in outcomes.items()
                  if o not in (SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_BRANCH)]
    # A candidate that only got here because it carries azure-wi-failed is not fresh work.
    # If its destination is later renamed, deleted or falls out of PAT visibility, a quiet
    # window contains nothing else, it classifies SKIP_UNKNOWN, and the fatal below would
    # exit 1 on every run forever — never re-verdicted, because it never reaches create_wi,
    # so only a manual tag edit in Mend could clear it. Loud, yes; fatal, no.
    fresh = [t for t in considered if t not in set(retry_only or [])]
    if considered and not routed:
        global_errors += 1
        if fresh:
            # Zero coverage among projects that reached a routing decision is never normal.
            # This must also be FATAL: logging at ERROR alone still lets main() advance the
            # global watermark and print "completed successfully" with exit 0, because
            # global_errors is imported by value.
            run_failed = True
            logger.error(f"{report} — nothing routed. Check MEND_BRANCHES "
                         f"('{conf.branches}') and the scan template's tag keys.")
        else:
            logger.error(f"{report} — nothing routed, and every candidate this window came "
                         f"from the retry queue ({TAG_FAILED}) rather than from a fresh scan. "
                         f"Not failing the run: a retry entry whose destination no longer "
                         f"exists would otherwise fail every run forever. Fix the routing "
                         f"tags in Mend, or remove {TAG_FAILED} from the project(s) above.")
    elif outcomes and not routed:
        logger.warning(f"{report} — nothing routed this window.")
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

    synced = 0
    state = fetch_project_tag_state()
    reset_on = conf.reset.lower() == "true"
    max_hours = try_or_error(lambda: int(conf.maxlookback), 720)
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
                         f"existing work items. Per-project sync state will not advance for it, "
                         f"so this window will be retried on the next run.")
            for token, _ in targets[azure_project]:
                record_verdict(token, VERDICT_FAILED, end_date, state)
            continue
        for token, route in targets[azure_project]:
            conf.reponame = route.repo
            project_start = project_window(token, state, end_date, max_hours, reset_on)
            verdict, message = create_wi(token, project_start, end_date, custom_flds, wi_type)
            logger.info(message)
            record_verdict(token, verdict, end_date, state)
            save_project_addr(token, state)
            synced += 1

    conf.azure_project = original_azure_project
    conf.reponame = original_reponame
    conf.azure_area = original_azure_area
    return f"{report}; {synced} Mend project(s) synced"


def run_sync(st_date: str, end_date: str, custom_flds: list, wi_type: str):
    global exist_wis, global_errors, run_failed, synced_projects
    run_failed = False
    synced_projects = []
    res = []
    state = fetch_project_tag_state()
    reset_on = conf.reset.lower() == "true"
    max_hours = try_or_error(lambda: int(conf.maxlookback), 720)
    floor = selection_floor(state, st_date, end_date, max_hours, reset_on, reset_back_time)
    logger.info("Getting a modified project list")
    modified_projects = get_prj_list_modified(floor, end_date)
    candidates = build_selection(modified_projects, state)
    logger.info(f"Selection mode: {'tag-based routing' if conf.routing.lower() == 'true' else 'token list'}")
    # Logged on both branches, before routing returns: without it a pipeline log cannot
    # answer "did enrichment run?", and 'off' is reached silently by an unexpanded
    # $(MEND_EPSS) / $(MEND_REACHABILITY) as well as by an explicit false.
    logger.info(f"Enrichment: EPSS {'on' if epss_enabled() else 'off'} (MEND_EPSS), "
                f"Reachability {'on' if reachability_enabled() else 'off'} (MEND_REACHABILITY)")
    sync_state_desc = "Mend project tags" if tag_state_available \
        else "unavailable — windows fall back to MEND_MAXLOOKBACK"
    logger.info(f"Sync state: {sync_state_desc}; window floor {floor} -> {end_date}")
    if conf.routing.lower() == "true":
        return run_sync_routed(candidates, end_date, custom_flds, wi_type,
                               retry_only=set(candidates) - set(modified_projects or []))
    if conf.wsproducttoken:
        expanded = expand_product_tokens(conf.wsproducttoken)
        if expanded is None:
            logger.error("Mend API call failed while expanding MEND_PRODUCTTOKEN.")
            exit(-1)
        res.extend(expanded)

    if conf.wsprojecttoken:
        res.extend(conf.wsprojecttoken.split(","))
    res = set(candidates).intersection(res) if res else candidates
    res = list(set(res) - set(conf.wsexcludetoken.split(",")))
    #deleted_items = get_deleted_items()
    exist_wis = get_exist_wi()
    if exist_wis is None:
        global_errors += 1
        run_failed = True
        exist_wis = []
        return (f"Aborted: could not read existing work items in Azure project "
                f"'{conf.azure_project}'. Skipping to avoid creating duplicates. "
                f"Per-project sync state will not advance; this window will be retried.")
    for prj_el in res:
        project_start = project_window(prj_el, state, end_date, max_hours, reset_on)
        verdict, message = create_wi(prj_el, project_start, end_date, custom_flds, wi_type)
        logger.info(message)
        record_verdict(prj_el, verdict, end_date, state)
        save_project_addr(prj_el, state)

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


def org_uuid() -> str:
    """The org identifier for 3.0's org-scoped paths.

    Defaults to MEND_APIKEY: the 1.4 org token and the 3.0 organization UUID are both the org's
    identifier from Mend's Administration screen and are plausibly the same value (spec gate G7,
    unverified against a live org). Defaulting means nobody sets MEND_ORGUUID unless they differ.
    Every 3.0 caller goes through here -- never read conf.org_uuid directly.
    """
    return (conf.org_uuid or conf.ws_org_token or "").strip()


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
        epss=varenvs.get_env("wsepss").strip(),
        reachability=varenvs.get_env("wsreachability").strip(),
        maxlookback=varenvs.get_env("wsmaxlookback").strip(),
        email=varenvs.get_env("wsemail").strip(),
        api_url=varenvs.get_env("wsapiurl").strip(),
        org_uuid=varenvs.get_env("wsorguuid").strip(),
        severity=varenvs.get_env("wsseverity").strip(),
    )
    try:
        return conf
    except Exception as err:
        logger.error(f"[{ex()}] Configuration validation failed: {err}")
        exit(-1)
