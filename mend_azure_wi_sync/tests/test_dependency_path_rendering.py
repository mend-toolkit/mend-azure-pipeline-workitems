"""generate_html_nested_list and library_block_v3's Dependency Hierarchy line.

Task 1 (source3.normalise_library_paths) turns the Mend 2.0 payload into ordered
root->leaf chains; Task 2 (core.attach_library_paths) attaches them to a TRANSITIVE
entry with a known uuid. This is the rendering half: chains -> nested <ul>/<li> HTML.

Placement note: test_dependency_paths.py (Task 1) is source3-only and imports nothing
from core -- it stays that way. The escaping-specific case lives in test_html_escaping.py
next to its sibling cases; the byte-identical-twice case lives in
test_description_stability.py next to the house pattern for that. Everything else about
generate_html_nested_list and library_block_v3's three-way branch lives here.
"""

from mend_azure_wi_sync import core


# --------------------------------------------------------------- generate_html_nested_list

def test_empty_paths_yields_empty_string():
    assert core.generate_html_nested_list([]) == ""


def test_none_paths_yields_empty_string():
    assert core.generate_html_nested_list(None) == ""


def test_single_path_nests_one_level_per_hop_root_and_leaf_labelled():
    html = core.generate_html_nested_list([["a", "b", "c"]], leaf_label="Vulnerable Library")
    assert html == (
        "<ul>\n"
        "  <li>a (Root Library)\n"
        "    <ul>\n"
        "      <li>b\n"
        "        <ul>\n"
        "          <li>c (Vulnerable Library)</li>\n"
        "        </ul>\n"
        "      </li>\n"
        "    </ul>\n"
        "  </li>\n"
        "</ul>\n"
    )


def test_seven_level_forever_chain_labels_only_root_and_leaf():
    chain = ["a", "b", "c", "d", "e", "f", "g"]
    html = core.generate_html_nested_list([chain], leaf_label="Vulnerable Library")
    assert html.count("<ul>") == 7
    assert html.count("</ul>") == 7
    assert "a (Root Library)" in html
    assert "g (Vulnerable Library)" in html
    # no interior node picks up either label
    for node in "bcdef":
        assert f"{node} (Root Library)" not in html
        assert f"{node} (Vulnerable Library)" not in html


def test_single_node_path_gets_root_label_only_never_both():
    html = core.generate_html_nested_list([["solo"]], leaf_label="Vulnerable Library")
    assert "solo (Root Library)" in html
    assert "Vulnerable Library" not in html


def test_leaf_label_empty_string_labels_root_and_leaves_leaf_bare():
    html = core.generate_html_nested_list([["a", "b"]], leaf_label="")
    assert "a (Root Library)" in html
    assert "<li>b</li>" in html


def test_two_paths_render_as_two_sibling_ul_blocks():
    html = core.generate_html_nested_list([["a", "b"], ["a", "c"]], leaf_label="Vulnerable Library")
    assert html.count("<ul>\n") == 4  # 2 outer + 2 inner, one per path
    assert "a (Root Library)" in html
    assert "b (Vulnerable Library)" in html
    assert "c (Vulnerable Library)" in html


def test_a_library_name_with_angle_brackets_amp_and_quote_is_escaped():
    html = core.generate_html_nested_list([["<script>", "a&b", "c\"d"]], leaf_label="Vulnerable Library")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "a&amp;b" in html
    assert "c&quot;d" in html


def test_rendering_the_same_paths_twice_is_byte_identical():
    paths = [["a", "b", "c"], ["a", "d", "c"]]
    first = core.generate_html_nested_list(paths, leaf_label="Vulnerable Library")
    second = core.generate_html_nested_list(paths, leaf_label="Vulnerable Library")
    assert first == second


# --------------------------------------------------------------- library_block_v3 branching

def _inputs(**overrides):
    values = {
        "library": "fastify", "description": "A framework", "dependency_file": "",
        "library_path": "", "home_page": "", "dependency_type": "", "parents": [],
        "paths": [],
    }
    values.update(overrides)
    return values


def test_paths_present_renders_hierarchy_heading_and_nested_list():
    inputs = _inputs(paths=[["app", "express", "fastify"]], dependency_type="Transitive")
    block = core.library_block_v3(inputs, with_hierarchy=True)
    assert "<br><b>Dependency Hierarchy: </b><br>" in block
    assert "<ul>" in block
    assert "app (Root Library)" in block


def test_paths_present_and_vulnerability_leaf_labels_leaf_vulnerable_library():
    inputs = _inputs(paths=[["app", "fastify"]], dependency_type="Transitive")
    block = core.library_block_v3(inputs, with_hierarchy=True, leaf_label="Vulnerable Library")
    assert "fastify (Vulnerable Library)" in block


def test_license_leaf_label_empty_leaves_leaf_bare():
    inputs = _inputs(paths=[["app", "fastify"]], dependency_type="Transitive")
    block = core.library_block_v3(inputs, with_hierarchy=True, leaf_label="")
    assert "<li>fastify</li>" in block
    assert "fastify (Vulnerable Library)" not in block


def test_transitive_with_parents_and_no_paths_uses_fallback_bulleted_list():
    inputs = _inputs(paths=[], dependency_type="Transitive", parents=["app > express"])
    block = core.library_block_v3(inputs, with_hierarchy=True)
    assert "<b>Dependency Hierarchy: </b>" in block
    assert "<ul>\n  <li>app &gt; express</li>\n</ul>" in block


def test_direct_dependency_omits_the_whole_hierarchy_line():
    inputs = _inputs(paths=[], dependency_type="Direct", parents=[])
    block = core.library_block_v3(inputs, with_hierarchy=True)
    assert "Dependency Hierarchy" not in block


def test_direct_dependency_with_stale_parents_still_omits_the_line():
    # dependency_type is what tells "direct" apart from "transitive call failed" -- an empty
    # paths list alone is ambiguous, per Task 2/3's interface contract.
    inputs = _inputs(paths=[], dependency_type="Direct", parents=["app > fastify"])
    block = core.library_block_v3(inputs, with_hierarchy=True)
    assert "Dependency Hierarchy" not in block


def test_with_hierarchy_false_never_renders_the_line_even_with_paths():
    inputs = _inputs(paths=[["app", "fastify"]], dependency_type="Transitive")
    block = core.library_block_v3(inputs, with_hierarchy=False)
    assert "Dependency Hierarchy" not in block


# --------------------------------------------------------------- Task 4: license items, via render_entry_v3

def _license_entry(**overrides):
    entry = {
        "library": "lodash", "kind": "license",
        "component": {"description": "A framework", "dependency_type": "Transitive",
                      "dependency_file": "package.json",
                      "library_path": "/app/node_modules/lodash",
                      "home_page": "https://lodash.com/"},
        "findings": [{"findingType": "LEGAL", "originName": "lodash",
                      "name": "[Legal] No copyleft", "uuid": "v-1"}],
        "licenses": [{"name": "GPL-3.0", "url": "https://spdx.org/gpl",
                      "reference_file": "pom.xml"}],
    }
    entry.update(overrides)
    return entry


def _render_license(entry):
    from unittest import mock
    conf = mock.MagicMock(dependency="true")
    with mock.patch.object(core, "conf", conf):
        return core.render_entry_v3("license", "lodash", entry, False)[0]["desc"]


def test_license_entry_with_paths_renders_nested_hierarchy_with_unlabelled_leaf():
    entry = _license_entry(paths=[["app", "express", "lodash"]])
    desc = _render_license(entry)
    assert "<br><b>Dependency Hierarchy: </b><br>" in desc
    assert "app (Root Library)" in desc
    assert "<li>lodash</li>" in desc
    assert "lodash (Vulnerable Library)" not in desc


def test_license_entry_without_paths_is_byte_identical_to_the_pre_task_4_baseline():
    """Baseline captured before flipping with_hierarchy on for the license branch (Task 4):
    with no paths and a license entry's parents always empty (render_inputs never populates
    them for kind == "license"), the hierarchy branch has nothing to render either way -- this
    pins that so the license description does not change shape for the common no-paths case."""
    entry = _license_entry()
    desc = _render_license(entry)
    baseline = (
        "<b>Library - </b>lodash<br>A framework<br>"
        "<b>Path to dependency file: </b>package.json<br>"
        "<b>Path to library:</b>/app/node_modules/lodash<br>"
        "<b>Vulnerable Library: </b>lodash<br>"
        "<b> Library home page: </b><a href='https://lodash.com/'>https://lodash.com/</a>"
        "<details>\n  <summary><b>License Details</b></summary>\n  "
        "<p><a href='https://spdx.org/gpl'>GPL-3.0</a><br>"
        "<b>License Reference File: </b><a href='pom.xml'>pom.xml</a><br>"
        "<b>License Policy Violation - </b>No copyleft<br></p>\n</details>"
    )
    assert desc == baseline
    assert "Dependency Hierarchy" not in desc


def test_root_grouping_vulnerability_description_is_unchanged_by_task_4():
    """Global Constraint 4: MEND_DEPENDENCY=true root-grouping vulnerability items are out of
    scope. This pins library_block_v3(root=True) -- the root-grouping call site -- to stay at
    with_hierarchy=False regardless of what Task 4 does to the license call site."""
    inputs = _inputs(paths=[["app", "express", "fastify"]], dependency_type="Transitive")
    block = core.library_block_v3(inputs, with_hierarchy=False, root=True)
    assert "Dependency Hierarchy" not in block
