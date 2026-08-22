from unittest import mock

from mend_azure_wi_sync import core


def _pages(*pages, total=None):
    """Each page is (items, next_cursor_or_None); returns a call_ws_api_v3 stub.

    `total` is the totalItems reported on every page's additionalData; it defaults to the true
    sum of items across all pages, so a caller only needs to override it to test a disagreement.
    """
    calls = []
    if total is None:
        total = sum(len(items) for items, _ in pages)

    def fake(api, params=None):
        idx = len(calls)
        calls.append((params or {}).get("cursor"))
        if idx >= len(pages):
            raise AssertionError(f"asked for page {idx}, only {len(pages)} defined")
        items, nxt = pages[idx]
        extra = {"totalItems": str(total)}
        if nxt is not None:
            extra["cursor"] = nxt
            extra["next"] = f"http://x?cursor={nxt}"
        return {"response": items, "additionalData": extra}, 0

    return fake, calls


def test_a_single_page_returns_its_items():
    fake, _ = _pages(([{"uuid": "a"}, {"uuid": "b"}], None))
    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert [i["uuid"] for i in items] == ["a", "b"]


def test_pages_are_followed_until_the_cursor_stops():
    fake, calls = _pages(([{"uuid": "a"}], 1), ([{"uuid": "b"}], 2), ([{"uuid": "c"}], None))
    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert [i["uuid"] for i in items] == ["a", "b", "c"]
    assert calls == [None, 1, 2], "first call must send no cursor, then the previous page's"


def test_an_empty_page_ends_the_walk():
    """A cursor that keeps being returned with no items must not loop forever."""
    fake, _ = _pages(([{"uuid": "a"}], 1), ([], 2))
    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert [i["uuid"] for i in items] == ["a"]


def test_a_failed_first_page_reports_not_ok():
    with mock.patch.object(core, "call_ws_api_v3", return_value=({"m": "boom"}, 2)):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False
    assert items == []


def test_a_failed_later_page_reports_not_ok_and_keeps_what_it_read():
    """Plan 4 closes work items absent from a fetch. A partial read must be distinguishable
    from a genuinely shorter one, or reconciliation closes items that still exist."""
    def fake(api, params=None):
        if not (params or {}).get("cursor"):
            return {"response": [{"uuid": "a"}], "additionalData": {"cursor": 1}}, 0
        return {"m": "boom"}, 2

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False
    assert [i["uuid"] for i in items] == ["a"]


def test_a_malformed_response_reports_not_ok_rather_than_empty_success():
    with mock.patch.object(core, "call_ws_api_v3", return_value=({"unexpected": True}, 0)):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False


def test_the_limit_is_passed_through():
    fake, _ = _pages(([{"uuid": "a"}], None))
    captured = {}

    def wrapper(api, params=None):
        captured.update(params or {})
        return fake(api, params)

    with mock.patch.object(core, "call_ws_api_v3", wrapper):
        core.fetch_v3_pages("orgs/o-1/projects", limit=250)
    assert captured["limit"] == 250


def test_a_runaway_cursor_is_bounded():
    """A server that always returns the same cursor and items must not hang the run."""
    def fake(api, params=None):
        return {"response": [{"uuid": "x"}], "additionalData": {"cursor": 7}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False, "hitting the page cap must report not-ok, never a clean partial"
    assert len(items) <= 1000 * core.MAX_V3_PAGES


def test_a_repeated_cursor_stops_after_a_few_calls_not_the_page_cap():
    """A repeated cursor must be caught immediately rather than spinning to MAX_V3_PAGES."""
    calls = []

    def fake(api, params=None):
        calls.append((params or {}).get("cursor"))
        return {"response": [{"uuid": "x"}], "additionalData": {"cursor": 7}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False
    assert len(calls) <= 3, "a repeat must short-circuit long before the 1000-page cap"


def test_total_items_agreeing_with_the_collected_count_stays_ok():
    fake, _ = _pages(([{"uuid": "a"}], 1), ([{"uuid": "b"}], None))
    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert [i["uuid"] for i in items] == ["a", "b"]


def test_total_items_disagreeing_with_the_collected_count_reports_not_ok():
    """The only server-side evidence a walk was complete is totalItems; a genuine mismatch means
    the read was truncated, so closures must be skipped."""
    fake, _ = _pages(([{"uuid": "a"}], None), total=5)
    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is False
    assert [i["uuid"] for i in items] == ["a"]


def test_missing_total_items_does_not_affect_ok():
    def fake(api, params=None):
        return {"response": [{"uuid": "a"}], "additionalData": {}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True


def test_unparseable_total_items_does_not_affect_ok():
    def fake(api, params=None):
        return {"response": [{"uuid": "a"}], "additionalData": {"totalItems": "many"}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True


def test_total_items_as_a_matching_string_stays_ok():
    def fake(api, params=None):
        return {"response": [{"uuid": "a"}, {"uuid": "b"}], "additionalData": {"totalItems": "2"}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert len(items) == 2


def test_a_genuinely_empty_project_with_total_items_zero_stays_ok():
    """Closures depend on an empty project reporting ok=True -- otherwise nothing ever gets
    reconciled for a project with no live entities left."""
    def fake(api, params=None):
        return {"response": [], "additionalData": {"totalItems": "0"}}, 0

    with mock.patch.object(core, "call_ws_api_v3", fake):
        items, ok = core.fetch_v3_pages("orgs/o-1/projects")
    assert ok is True
    assert items == []
