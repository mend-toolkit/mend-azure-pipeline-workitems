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
from reconcile import CLOSE, CREATE, REOPEN, SKIP, UPDATE, plan_actions
from routing import (parse_route, build_table, coverage_report, LOUD_OUTCOMES,
                     SKIP_EXCLUDED, SKIP_OUT_OF_SCOPE, SKIP_OK, SKIP_UNKNOWN, SKIP_BRANCH)
from source3 import (library_url, license_policy_name, normalise_findings, normalise_licenses,
                     normalise_projects, normalise_violations, render_inputs, select_projects,
                     severity_floor)
from syncstate import (TAG_FAILED, TAG_LASTRUN, VERDICT_FAILED,
                       VERDICT_OK, build_selection, failed_stamp, is_stale,
                       count_parseable_rows, field_for, parse_tag_map,
                       parse_raw_tags, parse_tag_values, selection_floor, superseded, tag_ops,
                       window_start)
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
# Only these two policy match types are supported: every other type renders no usable work
# item content, so creating one orphans it.
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
                               # memoized so the routed and unrouted selection paths don't
                               # each pay one Mend call per product token in the same run. Only a
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
    """{token: {lastrun, failed}} for the whole org, read once per run.

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
    # mend_api_url(), NOT conf.ws_url: 2.0 lives on api-saas.mend.io while 1.4 lives on the
    # SCA app host. See the spec's servers block.
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
    """A work item title -> (kind, library), or None if it is not one of ours.

    Inverts the two shipped title formats:
      "License Policy Violation detected in {lib}"                        -> license
      "{lib}: {N} vulnerabilities (highest severity is {S})"              -> vulnerability
    """
    text = (title or "").strip()
    prefix = "License Policy Violation detected in "
    if text.startswith(prefix):
        lib = text[len(prefix):].strip()
        return ("license", lib) if lib else None
    head = text.split(":", 1)[0].strip()
    if head and matches_library(text, head):
        return ("vulnerability", head)
    return None


def actual_work_items(project_name: str):
    """{(kind, library): {"id", "state"}} for the live work items belonging to one Mend project.

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
            # Two live work items for one (kind, library). The winner is the LOWEST id, so the
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

    CREATE and UPDATE are counted and reported but deliberately NOT executed here. create_wi /
    create_wi_content are built end to end around Mend 1.4 policy-issue objects -- the HTML
    tables, the CVE sections, the custom-field resolution, the tags and the Hyperlink relation
    to the library's Mend page. Feeding 3.0 entries through them is a rendering rewrite, not a
    wiring change. Creation keeps working on the existing 1.4 forward-sync path;
    this function adds only the closure half.

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
    azure_project) tuples create_wi appends. That third element is the join that makes this
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


# The work item rendering helpers below were nested inside create_wi. They are lifted to
# module level UNCHANGED so the 3.0 creation path (create_wi_v3) can reuse the exact same
# renderers rather than reimplementing them -- two implementations of a shipped work item
# description would drift. Anything that genuinely reads create_wi's closure (the 1.4
# fetchers, create_wi_content, field_name_in_data, find_parent_chain) stays where it is.


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

    def field_name_in_data(fld_name: str):  # Don't need to add existing element to data
        res = False
        for el_ in data:
            if fld_name in el_["path"]:
                res = True
                break
        return res

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

    def create_wi_content():
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
            desc_field = get_field_ref(conf.description, cstm_flds)
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
                if lib_url:
                    # Standalone value: the operator's one click from the work item to the
                    # library in Mend. Deliberately NO attributes.comment -- that carried
                    # "{projectToken},{issueUuid}" for the reverse sync, which no longer exists
                    # and nothing reads.
                    data.append(
                        {
                            "op": "add",
                            "path": "/relations/-",
                            "value": {
                                "rel": "Hyperlink",
                                "url": lib_url
                            }
                        }
                    )
                r, errcode = call_azure_api(api_type="POST", api=f"wit/workitems/${wi_type}", data=data,
                                            project=conf.azure_project)
                try:
                    exist_wis.append({vul_title: {r["id"]: {
                        "tags": ",".join(tags),
                        "state": try_or_error(lambda: r["fields"]["System.State"], "")}}})
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
                        exist_wis.append({vul_title: {exist_id: {
                            "tags": ",".join(tags),
                            "state": try_or_error(lambda: r["fields"]["System.State"], "")}}})
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
            # The library's Mend page. It is the operator's click-through link out of the work
            # item, written below as a Hyperlink relation. It used to double as the reverse
            # sync's carrier (attributes.comment = "{token},{uuid}"); the reverse sync is gone,
            # the link is not.
            lib_url = try_or_error(lambda: prj_el["library"]["url"], "")
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
                        create_wi_content()
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
                                create_wi_content()
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
        # Written unconditionally, whatever the verdict: this is the run's record of which
        # Mend projects resolved to which Azure project, keyed by the same (product, project)
        # tag string create_wi writes onto the work items themselves.
        synced_projects.append((prj_token, f"{prd_name}/{prj_name}", conf.azure_project))
        return (VERDICT_FAILED if item_failed else VERDICT_OK), message
    except Exception as err:
        return VERDICT_FAILED, f"[{ex()}] Work item creation failed: {err}"



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

    "exact" says how the item is matched against what Azure already holds: a dependency-mode
    vulnerability title carries a finding count and a max score, both of which move on every
    rescore, so it matches on the library name alone (identity.matches_library). Licences and
    per-CVE titles have no moving parts and match exactly. Same rule as the 1.4 path.
    """
    inputs = render_inputs(entry)
    rows = inputs["vulnerabilities"]
    licenses = entry.get("licenses") or [] if isinstance(entry, dict) else []

    if kind == "license":
        desc = library_block_v3(inputs, with_hierarchy=False) + \
            build_license_html_v3(licenses, license_policy_name(entry))
        return [{"title": license_title(library), "desc": desc, "score": "", "exact": True}]

    if conf.dependency.lower() == "true":
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
                      "desc": desc, "score": row.get("score", ""), "exact": True})
    return items


def write_wi_v3(item: dict, tags: list, lib_url: str, cstm_flds: list, wi_type: str,
                project_name: str):
    """Create or update ONE work item from a rendered 3.0 item. Returns "created", "updated"
    or "failed".

    Matching, the wrong-type DELETE-and-recreate, and the exist_wis cache refresh are all
    identical to create_wi's -- the 1.4 and 3.0 paths must agree on which work item a title
    identifies, or the changeover in Task 4 orphans every item the 1.4 path created.
    """
    global global_errors, exist_wis, updated_wi
    title = item["title"]
    if item["exact"]:
        exist_id = check_wi_id(id=title, project_name=project_name)
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

    Returns (created, updated, failed). The 3.0 twin of create_wi: it renders the SAME work
    items from 3.0 findings instead of 1.4 policy issues, reusing the same renderers, the same
    matching and the same tags, so a backlog created by the 1.4 path is picked up rather than
    duplicated when Task 4 changes the wiring.

    NO CALLERS until Task 4 -- this ships alongside create_wi, which is still the live path.
    """
    global conf
    conf = startup() if not conf else conf
    project_name = f"{project.get('application_name', '')}/{project.get('name', '')}"
    reachability_on = reachability_enabled()
    created = updated = failed = 0
    for (kind, library), entry in (desired or {}).items():
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
                         f"{kind} '{library}' in {project_name}: {err}")
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
    logger.info(f"Enrichment: EPSS {'on' if epss_enabled() else 'off'} (MEND_EPSS), "
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

    Keyed by (kind, library) rather than library: one library can carry both a vulnerability and
    a license work item, and they are separate items with different titles.

    Every entry carries "licenses" (a list, [] when the library has none) so downstream
    rendering never has to guard for the key's absence.
    """
    findings, findings_ok = fetch_v3_pages(
        f"projects/{project_uuid}/dependencies/findings/security")
    violations, violations_ok = fetch_v3_pages(
        f"orgs/{org_uuid()}/projects/{project_uuid}/violations")
    licenses, licenses_ok = fetch_v3_licenses(project_uuid)

    vuln_entries, unscored = normalise_findings(findings, floor)
    lic_entries = normalise_violations(violations)

    if unscored:
        # Spec 5.1 requires this to be an explicit rule, not an accident of a missing key.
        logger.info(f"[{fn()}] {unscored} unscored vulnerability finding(s) in project "
                    f"{project_uuid} were INCLUDED: they cannot be compared to MEND_SEVERITY, "
                    f"and a real finding vanishing because Mend has not scored it yet is the "
                    f"worse failure.")

    desired = {}
    for lib, entry in vuln_entries.items():
        entry["licenses"] = licenses.get(lib, [])
        desired[("vulnerability", lib)] = entry
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
