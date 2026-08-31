"""normalise_library_paths: the Mend 2.0 dependency-path payload -> ordered chains of names.

{"retVal": [{"libraryPath": [{uuid, name, order}, ...]}, ...]} -> [[name, name, ...], ...].

Global Constraint 1 binds this function: retVal's own order is TRUSTED and never sorted, only
the nodes WITHIN a path are sorted, by "order". See source3.py's module docstring for why this
module stays pure -- no HTTP, no conf, no logging.
"""

from mend_azure_wi_sync import source3


def _node(name, order, uuid="u"):
    return {"uuid": uuid, "name": name, "order": order}


def test_live_payload_normalises_to_two_expected_chains_in_retval_order():
    payload = {
        "retVal": [
            {"libraryPath": [_node("app", 0), _node("express", 1), _node("body-parser", 2)]},
            {"libraryPath": [_node("app", 0), _node("webpack", 1), _node("body-parser", 2)]},
        ]
    }
    assert source3.normalise_library_paths(payload) == [
        ["app", "express", "body-parser"],
        ["app", "webpack", "body-parser"],
    ]


def test_nodes_are_sorted_by_order_even_when_shuffled():
    payload = {"retVal": [
        {"libraryPath": [_node("body-parser", 2), _node("app", 0), _node("express", 1)]},
    ]}
    assert source3.normalise_library_paths(payload) == [["app", "express", "body-parser"]]


def test_nodes_sharing_an_order_keep_arrival_sequence():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), _node("first", 1), _node("second", 1)]},
    ]}
    assert source3.normalise_library_paths(payload) == [["app", "first", "second"]]


def test_missing_or_non_integer_order_is_treated_as_zero():
    payload = {"retVal": [
        {"libraryPath": [{"uuid": "u", "name": "no-order"},
                          {"uuid": "u", "name": "bad-order", "order": "nope"},
                          _node("has-order", 0)]},
    ]}
    # all three effectively order 0 -> arrival order preserved
    assert source3.normalise_library_paths(payload) == [["no-order", "bad-order", "has-order"]]


def test_duplicate_identical_chains_collapse_to_one_keeping_first_seen_position():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), _node("express", 1)]},
        {"libraryPath": [_node("app", 0), _node("webpack", 1)]},
        {"libraryPath": [_node("app", 0), _node("express", 1)]},
    ]}
    assert source3.normalise_library_paths(payload) == [
        ["app", "express"],
        ["app", "webpack"],
    ]


def test_chains_differing_by_one_hop_both_survive():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), _node("express", 1), _node("qs", 2)]},
        {"libraryPath": [_node("app", 0), _node("webpack", 1), _node("qs", 2)]},
    ]}
    result = source3.normalise_library_paths(payload)
    assert len(result) == 2
    assert result[0] != result[1]


def test_none_payload_yields_empty_list():
    assert source3.normalise_library_paths(None) == []


def test_non_dict_payload_yields_empty_list():
    assert source3.normalise_library_paths("nope") == []
    assert source3.normalise_library_paths([1, 2, 3]) == []


def test_missing_retval_yields_empty_list():
    assert source3.normalise_library_paths({}) == []


def test_non_list_retval_yields_empty_list():
    assert source3.normalise_library_paths({"retVal": "nope"}) == []
    assert source3.normalise_library_paths({"retVal": None}) == []


def test_entries_with_missing_or_non_list_library_path_are_skipped():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), _node("express", 1)]},
        {"libraryPath": "nope"},
        {},
        "not-a-dict",
        {"libraryPath": None},
    ]}
    assert source3.normalise_library_paths(payload) == [["app", "express"]]


def test_a_node_with_no_name_is_skipped():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), {"uuid": "u", "order": 1}, _node("express", 2)]},
    ]}
    assert source3.normalise_library_paths(payload) == [["app", "express"]]


def test_a_node_that_is_not_a_dict_is_skipped():
    payload = {"retVal": [
        {"libraryPath": [_node("app", 0), "not-a-dict", _node("express", 2)]},
    ]}
    assert source3.normalise_library_paths(payload) == [["app", "express"]]


def test_a_path_that_is_empty_after_filtering_is_skipped():
    payload = {"retVal": [
        {"libraryPath": [{"uuid": "u"}, {"uuid": "u2"}]},
        {"libraryPath": [_node("app", 0)]},
    ]}
    assert source3.normalise_library_paths(payload) == [["app"]]


def test_never_raises_on_thoroughly_malformed_input():
    assert source3.normalise_library_paths({"retVal": [None, 1, "nope", {"libraryPath": [1, 2]}]}) == []
