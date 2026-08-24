"""_fetch_paths_batch (Task 1: concurrent /paths fetch), the request timeout (Task 2), MEND_DEPPATHS
(Task 4: kill switch) and MEND_DEPPATHS_CONCURRENCY (the pool-size override added mid-task) --
see the dep-paths-perf brief.

attach_library_paths' selection/skip logic and the breaker's reviewed semantics are exercised in
test_source3_fetch.py, right next to fetch_v2_library_paths, which this whole change deliberately
never touches. This file is everything downstream of selection: the fan-out itself, the JWT
pre-warm, the 401/403 retry pass, the per-call timeout, the two kill switches, and the proof that
none of this changes a single byte of a rendered description.
"""
from unittest import mock

import pytest

from mend_azure_wi_sync import core


@pytest.fixture(autouse=True)
def _reset_state():
    core.library_paths_cache = {}
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False
    core.mend_v2_session = None
    yield
    core.library_paths_cache = {}
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False
    core.mend_v2_session = None


def _conf(dep_paths="", dep_paths_concurrency=""):
    return mock.MagicMock(ws_url="saas.mend.io", proxy={}, dep_paths=dep_paths,
                          dep_paths_concurrency=dep_paths_concurrency)


def _ok(uuid_="u1"):
    return {"retVal": [{"libraryPath": [{"uuid": uuid_, "name": "app", "order": 0}]}]}, 0


def _license_entry(library_uuid="lib-1", dependency_type="Transitive"):
    return {"kind": "license", "library": "log4j-core", "findings": [],
           "component": {"dependency_type": dependency_type, "library_uuid": library_uuid}}


# ------------------------------------------------------------------- Task 1: fan-out / batching

def test_n_distinct_uuids_yield_n_http_calls():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           side_effect=lambda url, token, params, timeout=None: _ok()) as get_mock:
        results = core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3"])
    assert get_mock.call_count == 3
    assert set(results.keys()) == {"lib-1", "lib-2", "lib-3"}


def test_prewarms_token_exactly_once_before_fanning_out():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1") as token_mock, \
         mock.patch.object(core, "_get_v2", return_value=_ok()):
        core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3", "lib-4"])
    token_mock.assert_called_once()


def test_no_uuids_makes_no_call_at_all():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token") as token_mock, \
         mock.patch.object(core, "_get_v2") as get_mock:
        results = core._fetch_paths_batch("proj-1", [])
    assert results == {}
    token_mock.assert_not_called()
    get_mock.assert_not_called()


def test_one_uuid_failing_does_not_affect_the_others():
    def fake_get(url, token, params, timeout=None):
        if "lib-2" in url:
            return {"error": "nope"}, 2
        return _ok()

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", fake_get):
        results = core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3"])
    assert results["lib-1"][1] == 0
    assert results["lib-2"][1] == 2
    assert results["lib-3"][1] == 0


# ------------------------------------------------------------------- Task 2: timeout

def test_timeout_is_passed_to_every_batch_call():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=_ok()) as get_mock:
        core._fetch_paths_batch("proj-1", ["lib-1"])
    _, kwargs = get_mock.call_args
    assert kwargs.get("timeout") == core.LIBRARY_PATHS_TIMEOUT


def test_get_v2_default_timeout_is_none_for_every_other_caller():
    """Task 2's constraint: _get_v2 grew an optional timeout parameter, but every existing
    caller (call_ws_api_v2, call_ws_api_v3, the 2.0 login) must stay byte-for-byte unaffected --
    i.e. still pass no timeout at all."""
    captured = {}

    def fake_requests_get(url, params=None, verify=None, proxies=None, timeout=None, headers=None):
        captured["timeout"] = timeout
        response = mock.MagicMock(status_code=200, text="{}")
        return response

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch("mend_azure_wi_sync.core.requests.get", fake_requests_get):
        core._get_v2("https://api-saas.mend.io/api/v2.0/x", "tok", {})
    assert captured["timeout"] is None


# ------------------------------------------------------------------- 401/403 re-login retry pass

def test_401_triggers_exactly_one_relogin_and_one_retry_pass_not_one_per_worker():
    token_calls = {"n": 0}

    def fake_token():
        token_calls["n"] += 1
        return "jwt-1" if token_calls["n"] == 1 else "jwt-2"

    def fake_get(url, token, params, timeout=None):
        if token == "jwt-1":
            return {"error": "expired"}, 401
        return _ok()

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", side_effect=fake_token), \
         mock.patch.object(core, "_get_v2", fake_get):
        results = core._fetch_paths_batch("proj-1", ["lib-1", "lib-2"])
    # One prewarm + one re-login -- never one login per failing worker.
    assert token_calls["n"] == 2
    assert results["lib-1"][1] == 0
    assert results["lib-2"][1] == 0


def test_403_is_treated_the_same_as_401():
    token_calls = {"n": 0}

    def fake_token():
        token_calls["n"] += 1
        return "jwt-1" if token_calls["n"] == 1 else "jwt-2"

    def fake_get(url, token, params, timeout=None):
        if token == "jwt-1":
            return {"error": "forbidden"}, 403
        return _ok()

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", side_effect=fake_token), \
         mock.patch.object(core, "_get_v2", fake_get):
        results = core._fetch_paths_batch("proj-1", ["lib-1"])
    assert token_calls["n"] == 2
    assert results["lib-1"][1] == 0


# ------------------------------------------------------------------- breaker: already tripped

def test_breaker_already_tripped_means_no_call_at_all():
    core.library_paths_breaker_tripped = True
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token") as token_mock, \
         mock.patch.object(core, "_get_v2") as get_mock:
        results = core._fetch_paths_batch("proj-1", ["lib-1", "lib-2"])
    assert results == {}
    token_mock.assert_not_called()
    get_mock.assert_not_called()


def test_breaker_trips_deterministically_then_a_later_call_makes_no_http_call():
    threshold = core.LIBRARY_PATHS_BREAKER_THRESHOLD
    desired = {("license", f"lib{i}"): _license_entry(library_uuid=f"lib-{i}")
              for i in range(threshold)}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"error": "nope"}, 2)) as get_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    assert core.library_paths_breaker_tripped is True
    assert get_mock.call_count == threshold

    desired2 = {("license", "libX"): _license_entry(library_uuid="lib-x")}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token") as token_mock2, \
         mock.patch.object(core, "_get_v2") as get_mock2:
        core.attach_library_paths("proj-1", desired2, per_cve=False)
    token_mock2.assert_not_called()
    get_mock2.assert_not_called()
    assert desired2[("license", "libX")]["paths"] == []


# ------------------------------------------------------------------- ok interlock

def test_ok_interlock_stays_true_across_a_failing_batch_fetch():
    desired = {("license", "log4j-core"): _license_entry()}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"error": "nope"}, 2)):
        core.attach_library_paths("proj-1", desired, per_cve=False)
    assert desired[("license", "log4j-core")]["paths"] == []


# ------------------------------------------------------------------- Task 4: kill switch

def test_kill_switch_off_makes_no_calls_and_sets_no_paths():
    desired = {("license", "log4j-core"): _license_entry()}
    with mock.patch.object(core, "conf", _conf(dep_paths="false")), \
         mock.patch.object(core, "mend_v2_token") as token_mock, \
         mock.patch.object(core, "_get_v2") as get_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    token_mock.assert_not_called()
    get_mock.assert_not_called()
    assert "paths" not in desired[("license", "log4j-core")]


def test_kill_switch_unset_behaves_exactly_as_default_on():
    desired = {("license", "log4j-core"): _license_entry()}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=_ok()) as get_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    get_mock.assert_called_once()
    assert desired[("license", "log4j-core")]["paths"]


@pytest.mark.parametrize("value", ["false", "False", "FALSE", "no", "No", "0"])
def test_dep_paths_enabled_is_false_for_falsey_values(value):
    with mock.patch.object(core, "conf", _conf(dep_paths=value)):
        assert core.dep_paths_enabled() is False


@pytest.mark.parametrize("value", ["", "true", "yes", "1", "garbage", "$(MEND_DEPPATHS)"])
def test_dep_paths_enabled_is_true_for_everything_else(value):
    with mock.patch.object(core, "conf", _conf(dep_paths=value)):
        assert core.dep_paths_enabled() is True


# ------------------------------------------------------------------- MEND_DEPPATHS_CONCURRENCY

def test_pool_size_defaults_to_16_when_unset():
    with mock.patch.object(core, "conf", _conf()):
        assert core.library_paths_pool_size() == 16 == core.LIBRARY_PATHS_POOL_SIZE


def test_pool_size_honours_an_explicit_value():
    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="4")):
        assert core.library_paths_pool_size() == 4


@pytest.mark.parametrize("value", ["nope", "-1", "0", "3.5"])
def test_pool_size_falls_back_to_default_and_logs_a_warning(value):
    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency=value)), \
         mock.patch.object(core, "logger") as logger_mock:
        assert core.library_paths_pool_size() == core.LIBRARY_PATHS_POOL_SIZE
    logger_mock.warning.assert_called_once()


def test_pool_size_clamps_a_value_above_the_maximum():
    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="5000")), \
         mock.patch.object(core, "logger") as logger_mock:
        assert core.library_paths_pool_size() == core.LIBRARY_PATHS_POOL_SIZE_MAX
    logger_mock.warning.assert_called_once()


def test_pool_size_of_one_is_honoured_and_still_fetches_everything():
    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="1")), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           side_effect=lambda url, token, params, timeout=None: _ok()) as get_mock:
        results = core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3"])
    assert get_mock.call_count == 3
    assert set(results.keys()) == {"lib-1", "lib-2", "lib-3"}


def test_an_explicit_pool_size_is_actually_used_to_size_the_executor():
    seen_max_workers = {}
    real_executor = core.ThreadPoolExecutor

    class _Spy(real_executor):
        def __init__(self, max_workers=None, *a, **kw):
            seen_max_workers["value"] = max_workers
            super().__init__(max_workers=max_workers, *a, **kw)

    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="2")), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           side_effect=lambda url, token, params, timeout=None: _ok()), \
         mock.patch.object(core, "ThreadPoolExecutor", _Spy):
        core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3", "lib-4", "lib-5"])
    assert seen_max_workers["value"] == 2


# ------------------------------------------------------------------- Task 3: debug summary log

def test_debug_summary_logs_calls_cache_hits_and_failures():
    core.library_paths_cache[("proj-1", "lib-cached")] = [["app", "cached"]]
    desired = {
        ("license", "log4j-core"): _license_entry(library_uuid="lib-1"),
        ("license", "cached-lib"): _license_entry(library_uuid="lib-cached"),
    }
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=_ok()), \
         mock.patch.object(core, "logger") as logger_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    messages = [c.args[0] for c in logger_mock.debug.call_args_list]
    assert any("1 /paths call(s) made" in m and "1 served from cache" in m and "0 failed" in m
               for m in messages)


# ------------------------------------------------------------------- byte-identical descriptions

def _full_license_entry(library_uuid="lib-1"):
    return {
        "kind": "license", "library": "lodash",
        "component": {"description": "A framework", "dependency_type": "Transitive",
                      "dependency_file": "package.json", "library_uuid": library_uuid,
                      "library_path": "/app/node_modules/lodash", "home_page": "https://lodash.com/"},
        "findings": [{"findingType": "LEGAL", "originName": "lodash",
                      "name": "[Legal] No copyleft", "uuid": "v-1"}],
        "licenses": [{"name": "GPL-3.0", "url": "https://spdx.org/gpl", "reference_file": "pom.xml"}],
    }


def _render(entry):
    conf = mock.MagicMock(dependency="true")
    with mock.patch.object(core, "conf", conf):
        return core.render_entry_v3("license", "lodash", entry, False)[0]["desc"]


_PAYLOAD = {"retVal": [
    {"libraryPath": [{"uuid": "u1", "name": "app", "order": 0},
                     {"uuid": "u2", "name": "express", "order": 1},
                     {"uuid": "u3", "name": "lodash", "order": 2}]},
]}


def test_descriptions_are_byte_identical_between_concurrent_and_serial_fetch():
    """The whole point of this change: same inputs, same bytes. entry["paths"] computed via the
    new concurrent attach_library_paths must render identically to entry["paths"] computed via
    the untouched, serial fetch_v2_library_paths."""
    concurrent_entry = _full_license_entry()
    desired = {("license", "lodash"): concurrent_entry}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=(_PAYLOAD, 0)):
        core.attach_library_paths("proj-1", desired, per_cve=False)
    concurrent_desc = _render(concurrent_entry)

    core.library_paths_cache = {}
    serial_entry = _full_license_entry()
    with mock.patch.object(core, "call_ws_api_v2", return_value=(_PAYLOAD, 0)):
        serial_entry["paths"] = core.fetch_v2_library_paths("proj-1", "lib-1")
    serial_desc = _render(serial_entry)

    assert concurrent_desc == serial_desc
    assert "Dependency Hierarchy" in concurrent_desc
