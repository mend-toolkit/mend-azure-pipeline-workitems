from unittest import mock

from mend_azure_wi_sync import core


def _conf():
    return mock.MagicMock(ws_user_key="uk", ws_org_token="ot")


def _entity(product_name, project_name, tags):
    return {"product": {"name": product_name},
           "project": {"name": project_name, "tags": tags}}


# ---------------------------------------------------------------------------
# fetch_project_tags — the 2.0 /entities sweep and the token -> tag-list join.
# Name resolution is stubbed via _resolve_project_names so these focus purely on the
# pagination/parsing/join behaviour of fetch_project_tags itself.
# ---------------------------------------------------------------------------

def test_project_with_tags_is_returned():
    tags = [{"key": "azure-project", "value": "Platform"}]
    names = {"tok-a": ("Product A", "Project A")}
    page = {"retVal": [_entity("Product A", "Project A", tags)],
           "additionalData": {"isLastPage": True}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)) as api:
        result = core.fetch_project_tags(["tok-a"])
    assert result == {"tok-a": tags}
    api.assert_called_once_with("orgs/ot/entities", {"pageSize": 1000, "page": 0})


def test_project_with_no_tags_returns_empty_list_not_absent():
    names = {"tok-b": ("Product A", "Project B")}
    page = {"retVal": [_entity("Product A", "Project B", [])],
           "additionalData": {"isLastPage": True}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)):
        result = core.fetch_project_tags(["tok-b"])
    assert result == {"tok-b": []}
    assert "tok-b" in result           # scanned-but-untagged must be present, not omitted


def test_token_absent_from_entities_response_gets_empty_list():
    """The token resolves to a name pair, but that pair never shows up in /entities."""
    names = {"tok-c": ("Product A", "Project C")}
    page = {"retVal": [_entity("Product A", "Project A", [{"key": "k", "value": "v"}])],
           "additionalData": {"isLastPage": True}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)):
        result = core.fetch_project_tags(["tok-c"])
    assert result == {"tok-c": []}


def test_unresolvable_token_gets_empty_list():
    """A token _resolve_project_names could not find a name for must not raise or vanish."""
    page = {"retVal": [], "additionalData": {"isLastPage": True}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)):
        result = core.fetch_project_tags(["tok-ghost"])
    assert result == {"tok-ghost": []}


def test_multipage_pagination_terminates_on_is_last_page():
    """isLastPage arrives as a real JSON bool in production; str(...).lower() must handle it,
    not just the string the 2.0 spec's own example shows. Page 1 is padded to a full page so the
    belt-and-braces short-row check does not itself terminate the sweep early."""
    page1_rows = [_entity(f"P{i}", f"J{i}", []) for i in range(1000)]
    page1_rows.append(_entity("Product A", "Project A", [{"key": "azure-project", "value": "X"}]))
    page1 = {"retVal": page1_rows, "additionalData": {"isLastPage": "false"}}
    page2 = {"retVal": [_entity("Product B", "Project B", [{"key": "azure-repo", "value": "Y"}])],
           "additionalData": {"isLastPage": True}}
    names = {"tok-a": ("Product A", "Project A"), "tok-b": ("Product B", "Project B")}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2",
                           side_effect=[(page1, 0), (page2, 0)]) as api:
        result = core.fetch_project_tags(["tok-a", "tok-b"])
    assert api.call_count == 2
    assert result["tok-a"] == [{"key": "azure-project", "value": "X"}]
    assert result["tok-b"] == [{"key": "azure-repo", "value": "Y"}]


def test_short_page_stops_even_if_is_last_page_says_false():
    """Belt-and-braces: a page shorter than pageSize ends the sweep regardless of the flag."""
    page = {"retVal": [_entity("Product A", "Project A", [])],
           "additionalData": {"isLastPage": "false"}}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)) as api:
        core.fetch_project_tags([])
    assert api.call_count == 1


def test_failed_entities_call_returns_none():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2", return_value=({"message": "boom"}, 2)):
        assert core.fetch_project_tags(["tok-a"]) is None


def test_failed_name_resolution_returns_none_and_skips_the_entities_call():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=None), \
         mock.patch.object(core, "call_ws_api_v2") as api:
        assert core.fetch_project_tags(["tok-a"]) is None
    api.assert_not_called()


def test_duplicate_name_pair_is_reported_loudly_and_returns_none_for_that_token():
    """Two /entities rows sharing the same (product, project) name must not let the join
    silently pick one of them for a token that resolves to that pair. The collision must be
    distinguishable from a genuinely untagged project, so the per-token value is None, not []."""
    dup_a = [{"key": "azure-project", "value": "A"}]
    dup_b = [{"key": "azure-project", "value": "B"}]
    page = {"retVal": [_entity("Product X", "Project X", dup_a),
                       _entity("Product X", "Project X", dup_b)],
           "additionalData": {"isLastPage": True}}
    names = {"tok-a": ("Product X", "Project X")}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)), \
         mock.patch.object(core, "logger") as logger:
        result = core.fetch_project_tags(["tok-a"])
    assert result == {"tok-a": None}
    assert logger.error.called


def test_collided_token_is_none_while_an_ordinary_untagged_token_in_the_same_response_is_empty():
    """The three-state contract in one response: a collision must not contaminate an unrelated,
    genuinely-untagged project's result, and the two must remain distinguishable."""
    dup_a = [{"key": "azure-project", "value": "A"}]
    dup_b = [{"key": "azure-project", "value": "B"}]
    page = {"retVal": [_entity("Product X", "Project X", dup_a),
                       _entity("Product X", "Project X", dup_b),
                       _entity("Product Y", "Project Y", [])],
           "additionalData": {"isLastPage": True}}
    names = {"tok-collided": ("Product X", "Project X"), "tok-plain": ("Product Y", "Project Y")}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value=names), \
         mock.patch.object(core, "call_ws_api_v2", return_value=(page, 0)):
        result = core.fetch_project_tags(["tok-collided", "tok-plain"])
    assert result["tok-collided"] is None
    assert result["tok-plain"] == []


# ---------------------------------------------------------------------------
# isLastPage permutations — pinned individually against a full-size page so the flag's own
# branch (not the belt-and-braces short-row fallback) is what each test proves.
# ---------------------------------------------------------------------------

_ABSENT = object()


def _full_page(is_last_page_value):
    rows = [_entity(f"P{i}", f"J{i}", []) for i in range(1000)]
    additional_data = {} if is_last_page_value is _ABSENT else {"isLastPage": is_last_page_value}
    return {"retVal": rows, "additionalData": additional_data}


def test_is_last_page_bool_true_stops_the_sweep():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_full_page(True), 0)) as api:
        core.fetch_project_tags([])
    assert api.call_count == 1


def test_is_last_page_bool_false_continues_the_sweep():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2",
                           side_effect=[(_full_page(False), 0), (_full_page(True), 0)]) as api:
        core.fetch_project_tags([])
    assert api.call_count == 2


def test_is_last_page_string_true_stops_the_sweep():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2",
                           return_value=(_full_page("true"), 0)) as api:
        core.fetch_project_tags([])
    assert api.call_count == 1


def test_is_last_page_string_false_continues_the_sweep():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2",
                           side_effect=[(_full_page("false"), 0), (_full_page(True), 0)]) as api:
        core.fetch_project_tags([])
    assert api.call_count == 2


def test_is_last_page_absent_falls_back_to_the_row_count_check():
    """No additionalData.isLastPage key at all — a full page must be treated as 'more to come',
    just like the documented-false case, rather than stopping on an absent flag."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "_resolve_project_names", return_value={}), \
         mock.patch.object(core, "call_ws_api_v2",
                           side_effect=[(_full_page(_ABSENT), 0), (_full_page(True), 0)]) as api:
        core.fetch_project_tags([])
    assert api.call_count == 2


# ---------------------------------------------------------------------------
# _resolve_project_names — the 1.4 getAllProducts + getAllProjects join key resolution.
# ---------------------------------------------------------------------------

def test_resolve_project_names_walks_products_until_found():
    products = {"products": [{"productName": "Product A", "productToken": "prd-a"},
                             {"productName": "Product B", "productToken": "prd-b"}]}
    prd_a_projects = {"projects": [{"projectName": "Project A", "projectToken": "tok-a"}]}
    prd_b_projects = {"projects": [{"projectName": "Project B", "projectToken": "tok-b"}]}
    import json as _json
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api",
                           side_effect=[_json.dumps(products), _json.dumps(prd_a_projects),
                                       _json.dumps(prd_b_projects)]) as api:
        result = core._resolve_project_names(["tok-a", "tok-b"])
    assert result == {"tok-a": ("Product A", "Project A"), "tok-b": ("Product B", "Project B")}
    assert api.call_count == 3


def test_resolve_project_names_stops_once_all_tokens_are_found():
    products = {"products": [{"productName": "Product A", "productToken": "prd-a"},
                             {"productName": "Product B", "productToken": "prd-b"}]}
    prd_a_projects = {"projects": [{"projectName": "Project A", "projectToken": "tok-a"}]}
    import json as _json
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api",
                           side_effect=[_json.dumps(products), _json.dumps(prd_a_projects)]) as api:
        result = core._resolve_project_names(["tok-a"])
    assert result == {"tok-a": ("Product A", "Project A")}
    assert api.call_count == 2          # products + one product's projects; product B unneeded


def test_resolve_project_names_empty_input_makes_no_calls():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api") as api:
        assert core._resolve_project_names([]) == {}
    api.assert_not_called()


def test_resolve_project_names_returns_none_when_products_call_fails():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api", return_value="not json"):
        assert core._resolve_project_names(["tok-a"]) is None


def test_resolve_project_names_returns_none_when_a_projects_call_fails():
    import json as _json
    products = {"products": [{"productName": "Product A", "productToken": "prd-a"}]}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api",
                           side_effect=[_json.dumps(products), "not json"]):
        assert core._resolve_project_names(["tok-a"]) is None


def test_resolve_project_names_leaves_unfound_tokens_out_of_the_map():
    """A token that belongs to no product in the org is simply absent from the map, not an
    error — fetch_project_tags treats that as no name, hence no tags, not a failure."""
    import json as _json
    products = {"products": [{"productName": "Product A", "productToken": "prd-a"}]}
    prd_a_projects = {"projects": [{"projectName": "Project A", "projectToken": "tok-a"}]}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_ws_api",
                           side_effect=[_json.dumps(products), _json.dumps(prd_a_projects)]):
        result = core._resolve_project_names(["tok-ghost"])
    assert result == {}
