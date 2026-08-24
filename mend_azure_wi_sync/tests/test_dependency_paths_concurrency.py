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
    core.reset_library_paths_pool_size_cache()
    yield
    core.library_paths_cache = {}
    core.library_paths_consecutive_failures = 0
    core.library_paths_breaker_tripped = False
    core.mend_v2_session = None
    core.reset_library_paths_pool_size_cache()


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
    """Uses far more uuids than the threshold (100, default pool size 16) -- with only
    `threshold` uuids (the original version of this test) the assertion `call_count ==
    threshold` passes trivially whether or not the breaker actually bounds the fetch, because a
    single wave of 5 was always going to be <= any pool size. This is the regression test for
    the CRITICAL review finding: batching the whole project into one pool.map() defeats the
    breaker (383 uuids -> 383 calls before the breaker was even consulted). Bounding to one wave
    (16 calls) is the fix; 100 uuids proves it's not just "small input happens to fit"."""
    threshold = core.LIBRARY_PATHS_BREAKER_THRESHOLD
    n = 100
    desired = {("license", f"lib{i}"): _license_entry(library_uuid=f"lib-{i}") for i in range(n)}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"error": "nope"}, 2)) as get_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    assert core.library_paths_breaker_tripped is True
    # Bounded to (at most) one pool-sized wave, nowhere near the 100 uuids offered -- this is the
    # amplification the review flagged (383 -> 766 calls) being fixed.
    assert threshold < get_mock.call_count <= core.LIBRARY_PATHS_POOL_SIZE
    assert get_mock.call_count == core.LIBRARY_PATHS_POOL_SIZE

    desired2 = {("license", "libX"): _license_entry(library_uuid="lib-x")}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token") as token_mock2, \
         mock.patch.object(core, "_get_v2") as get_mock2:
        core.attach_library_paths("proj-1", desired2, per_cve=False)
    token_mock2.assert_not_called()
    get_mock2.assert_not_called()
    assert desired2[("license", "libX")]["paths"] == []


def test_a_permission_denial_storm_is_bounded_to_one_wave_plus_one_capped_retry():
    """The exact scenario from the review: a PAT lacking Mend 2.0 permission on a large project,
    where every call comes back 403 (indistinguishable from an expired JWT, so the batch fetch
    retries once). 383 uuids -- the size of the project that stalled a real pipeline run --
    must cost nowhere near 383 (let alone 766) calls."""
    desired = {("license", f"lib{i}"): _license_entry(library_uuid=f"lib-{i}")
              for i in range(383)}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", return_value=({"error": "forbidden"}, 403)) as get_mock:
        core.attach_library_paths("proj-1", desired, per_cve=False)
    assert core.library_paths_breaker_tripped is True
    # One wave (<=16) fetched, all 403 -> one capped retry of just that wave's uuids (<=16) with
    # the refreshed token, still 403 -> breaker trips before wave 2 is ever submitted.
    assert get_mock.call_count <= 2 * core.LIBRARY_PATHS_POOL_SIZE
    assert get_mock.call_count < 383


# ------------------------------------------------------------------- ok interlock

def _dd_row():
    """One DueDiligenceDTOV3 row -- carries a Transitive, uuid-bearing component, so the license
    entry it produces is exactly the kind attach_library_paths will attempt to fetch (unlike a
    bare _license_entry() dict handed straight to attach_library_paths, which never exercises
    fetch_v3_desired's real assembly, including the interlock, at all)."""
    return {
        "name": "GPL-3.0",
        "component": {"name": "log4j-core", "uuid": "lib-uuid-log4j-core", "version": "2.14.1",
                      "description": "Apache Log4j Core", "dependencyType": "Transitive",
                      "dependencyFile": "/src/pom.xml",
                      "localPath": "/root/.m2/log4j-core-2.14.1.jar",
                      "references": {"homePage": "https://logging.apache.org/log4j/"}},
        "license": {"textUrl": "https://opensource.org/licenses/GPL-3.0",
                    "liabilityReference": "/src/pom.xml"},
    }


def test_ok_interlock_stays_true_when_fetch_v3_desired_drives_a_failing_batch_fetch():
    """The full run path, not just attach_library_paths called in isolation: fetch_v3_desired's
    `ok` must stay True even though every /paths call the batch fetch makes genuinely fails.
    (The interlock itself -- attach_library_paths' return value discarded -- lives at
    core.py:2830 and was verified by inspection; this proves it end to end.)"""
    def fake_pages(api, params=None, limit=1000, method="GET"):
        if api.endswith("groupBy/rootLibrary"):
            return [], True
        if "findings/security" in api:
            return [], True
        if api.endswith("libraries/licenses"):
            return [_dd_row()], True
        if api.endswith("/violations"):
            return [{"findingType": "LEGAL", "originName": "log4j-core", "name": "GPL-3.0"}], True
        return [], True

    conf = _conf()
    conf.dependency = "false"
    with mock.patch.object(core, "conf", conf), \
         mock.patch.object(core, "fetch_v3_pages", fake_pages), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           return_value=({"error": "nope"}, 2)) as get_mock:
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    # The failure genuinely happened, on a real entry -- not skipped before ever reaching the
    # fetch -- so the interlock was actually exercised under failure, not just left untouched.
    get_mock.assert_called_once()
    assert desired[("license", "log4j-core")]["paths"] == []


# ------------------------------------------------------------------- successes past the trip point

def test_successful_results_already_fetched_are_applied_even_past_the_trip_point():
    """MINOR review finding: a mid-wave trip must not discard successful results the wave already
    paid for. Five failing uuids reach the threshold and trip the breaker mid-wave; a sixth uuid
    in the SAME wave that succeeds must still get its real paths cached and assigned -- only
    further FETCHING (a next wave, or a next attach_library_paths call) is what stops."""
    threshold = core.LIBRARY_PATHS_BREAKER_THRESHOLD
    desired = {("license", f"lib{i}"): _license_entry(library_uuid=f"lib-{i}")
              for i in range(threshold)}
    desired[("license", "libOK")] = _license_entry(library_uuid="lib-ok")

    def fake_get(url, token, params, timeout=None):
        if "lib-ok" in url:
            return _ok("u-ok")
        return {"error": "nope"}, 2

    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency=str(threshold + 1))), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2", fake_get):
        core.attach_library_paths("proj-1", desired, per_cve=False)
    assert core.library_paths_breaker_tripped is True
    # "lib-ok" sorts after "lib-0".."lib-4" and is in the same (only) wave -- its real, already-
    # fetched success must be applied, not thrown away because the breaker tripped on an earlier
    # uuid in the same wave.
    assert desired[("license", "libOK")]["paths"] == [["app"]]
    for i in range(threshold):
        assert desired[("license", f"lib{i}")]["paths"] == []


# ------------------------------------------------------------------- _get_v2 thread safety (batch path)

def test_batch_path_get_v2_skips_the_shared_warnings_recorder():
    """IMPORTANT review finding: warnings.catch_warnings(record=True) swaps process-wide state
    (the filter list, warnings.showwarning) on __enter__/__exit__, which is not thread-safe --
    concurrent workers could race each other's save/restore. The fix: any call that passes a
    timeout (i.e. only the batch /paths path) skips that block entirely. This proves the
    request still goes through and is parsed correctly without touching `warnings` at all."""
    import warnings as warnings_module

    entered = {"n": 0}
    real_catch_warnings = warnings_module.catch_warnings

    class _CountingCatchWarnings:
        def __init__(self, *a, **kw):
            self._real = real_catch_warnings(*a, **kw)

        def __enter__(self):
            entered["n"] += 1
            return self._real.__enter__()

        def __exit__(self, *a):
            return self._real.__exit__(*a)

    def fake_requests_get(url, params=None, verify=None, proxies=None, timeout=None, headers=None):
        return mock.MagicMock(status_code=200, text='{"retVal": []}')

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch("mend_azure_wi_sync.core.requests.get", fake_requests_get), \
         mock.patch.object(warnings_module, "catch_warnings", _CountingCatchWarnings):
        payload, errorcode = core._get_v2("https://api-saas.mend.io/api/v2.0/x", "tok", {},
                                          timeout=core.LIBRARY_PATHS_TIMEOUT)
    assert errorcode == 0
    assert payload == {"retVal": []}
    assert entered["n"] == 0


def test_non_batch_get_v2_still_uses_the_warnings_recorder():
    """The flip side: every OTHER _get_v2 caller (no timeout passed) is unaffected -- still goes
    through the recording block, exactly as before this change."""
    import warnings as warnings_module

    entered = {"n": 0}
    real_catch_warnings = warnings_module.catch_warnings

    class _CountingCatchWarnings:
        def __init__(self, *a, **kw):
            self._real = real_catch_warnings(*a, **kw)

        def __enter__(self):
            entered["n"] += 1
            return self._real.__enter__()

        def __exit__(self, *a):
            return self._real.__exit__(*a)

    def fake_requests_get(url, params=None, verify=None, proxies=None, timeout=None, headers=None):
        return mock.MagicMock(status_code=200, text='{"retVal": []}')

    with mock.patch.object(core, "conf", _conf()), \
         mock.patch("mend_azure_wi_sync.core.requests.get", fake_requests_get), \
         mock.patch.object(warnings_module, "catch_warnings", _CountingCatchWarnings):
        core._get_v2("https://api-saas.mend.io/api/v2.0/x", "tok", {})
    assert entered["n"] == 1


# ------------------------------------------------------------------- pool size resolved once per run

def test_pool_size_warning_logs_once_across_many_projects_in_one_run():
    """MINOR review finding: a junk MEND_DEPPATHS_CONCURRENCY must log its fallback warning once
    per RUN, not once per project (up to 107 times in a real org). library_paths_pool_size() is
    memoised until reset_library_paths_pool_size_cache() is called (as run_sync does once at the
    start of a run) -- simulating several projects here means several calls with no reset
    between them."""
    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="not-a-number")), \
         mock.patch.object(core, "logger") as logger_mock:
        for _ in range(5):
            assert core.library_paths_pool_size() == core.LIBRARY_PATHS_POOL_SIZE
    logger_mock.warning.assert_called_once()


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
    """5 uuids at pool size 2 -> waves of [2, 2, 1]: the executor is never asked for more than 2
    workers at once, even though the largest wave is exactly the pool size."""
    seen_max_workers = []
    real_executor = core.ThreadPoolExecutor

    class _Spy(real_executor):
        def __init__(self, max_workers=None, *a, **kw):
            seen_max_workers.append(max_workers)
            super().__init__(max_workers=max_workers, *a, **kw)

    with mock.patch.object(core, "conf", _conf(dep_paths_concurrency="2")), \
         mock.patch.object(core, "mend_v2_token", return_value="jwt-1"), \
         mock.patch.object(core, "_get_v2",
                           side_effect=lambda url, token, params, timeout=None: _ok()), \
         mock.patch.object(core, "ThreadPoolExecutor", _Spy):
        core._fetch_paths_batch("proj-1", ["lib-1", "lib-2", "lib-3", "lib-4", "lib-5"])
    assert max(seen_max_workers) == 2
    assert seen_max_workers == [2, 2, 1]


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
