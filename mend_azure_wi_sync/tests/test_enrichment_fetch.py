import itertools
from unittest import mock

from mend_azure_wi_sync import core


def _finding(name, uuid="lib-1"):
    return {"name": name, "component": {"uuid": uuid}, "reachability": "REACHABLE"}


def _page(findings, cursor=None):
    return {"response": findings, "additionalData": {"cursor": cursor} if cursor else {}}


def test_findings_are_read_from_the_response_envelope():
    with mock.patch.object(core, "call_ws_api_v3",
                           return_value=(_page([_finding("CVE-1")]), 0)):
        assert core.fetch_project_enrichment("uuid-1") == {
            ("CVE-1", "lib-1"): {"reachability": "REACHABLE"}}


def test_a_full_page_is_followed_by_a_cursored_request():
    limit = int(core.ENRICHMENT_PAGE_LIMIT)
    full = [_finding(f"CVE-{i}") for i in range(limit)]
    pages = [(_page(full, cursor="c1"), 0), (_page([_finding("CVE-last")], "c2"), 0)]
    with mock.patch.object(core, "call_ws_api_v3", side_effect=pages) as call:
        result = core.fetch_project_enrichment("uuid-1")
    assert ("CVE-last", "lib-1") in result
    assert "cursor" not in call.call_args_list[0][0][1]   # first call carries no cursor
    assert call.call_args_list[1][0][1]["cursor"] == "c1"


def test_a_cursor_repeated_on_the_last_page_terminates():
    # The cursor points at the LAST ITEM RETRIEVED, so it is present on the final page.
    # Without the repeat check this loops until the page cap, or forever.
    limit = int(core.ENRICHMENT_PAGE_LIMIT)
    full = [_finding(f"CVE-{i}") for i in range(limit)]
    with mock.patch.object(core, "call_ws_api_v3",
                           return_value=(_page(full, cursor="same"), 0)) as call:
        core.fetch_project_enrichment("uuid-1")
    assert call.call_count == 2


def test_the_page_cap_bounds_a_runaway_walk():
    limit = int(core.ENRICHMENT_PAGE_LIMIT)
    # Unbounded: each simulated page draws `limit` + 1 values, so a finite range would run
    # out well before the page cap is reached and this must instead prove the cap holds.
    cursors = itertools.count()
    def _call(api, params=None):
        return _page([_finding(f"CVE-{next(cursors)}") for _ in range(limit)],
                     cursor=f"c{next(cursors)}"), 0
    with mock.patch.object(core, "call_ws_api_v3", side_effect=_call) as call:
        core.fetch_project_enrichment("uuid-1")
    assert call.call_count == core.ENRICHMENT_MAX_PAGES


def test_failures_and_malformed_payloads_return_what_arrived():
    with mock.patch.object(core, "call_ws_api_v3", return_value=({}, 2)):
        assert core.fetch_project_enrichment("uuid-1") == {}
    with mock.patch.object(core, "call_ws_api_v3", return_value=({"nope": 1}, 0)):
        assert core.fetch_project_enrichment("uuid-1") == {}
    with mock.patch.object(core, "call_ws_api_v3", return_value=(_page([]), 0)):
        assert core.fetch_project_enrichment("uuid-1") == {}


def test_the_limit_is_sent_as_a_string():
    # The 3.0 spec types limit as a string with default "50"; at the default a 2,000-finding
    # project would cost 40 requests.
    with mock.patch.object(core, "call_ws_api_v3", return_value=(_page([]), 0)) as call:
        core.fetch_project_enrichment("uuid-1")
    assert call.call_args[0][1]["limit"] == core.ENRICHMENT_PAGE_LIMIT
    assert isinstance(core.ENRICHMENT_PAGE_LIMIT, str)
