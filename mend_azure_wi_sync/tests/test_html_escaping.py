"""Mend-supplied text is escaped before it goes into a description.

Live evidence that this is data loss, not tidiness. A work item whose CVE description reads
"<2.0.1, >=3.0.0 <4.0.1. A type confusion vulnerability can lead to ..." came back from Azure as:

    sent  '<2.0.1, >=3.0.0 <4.0.1. A type confusion vulnerability can l'
    azure '=3.0.0 Publish Date: 2021-09-12T12:55:10Z URL: CVE-2021-2344'

Azure parsed "<2.0.1, >" as a tag and dropped it, then ate "<4.0.1. A type confusion ..." up to
the next ">". The text is GONE from the stored work item -- operators are reading truncated
vulnerability descriptions. Version ranges ("<2.0.1", "<=1.2.5") and enrichment.EPSS_BELOW_ONE
("<1%") make this common rather than exotic.

So every Mend-supplied value is escaped at the point it is interpolated. The markup this tool
builds is NOT escaped -- only the data going into it. That makes the HTML valid, makes what Azure
stores match what was sent, and above all stops Azure deleting sentences out of descriptions.
"""

from unittest import mock

from mend_azure_wi_sync import core, source3


ANGLED = "<2.0.1, >=3.0.0 <4.0.1. A type confusion vulnerability can lead to RCE"


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="true", reponame="",
                  routing="false", description="ReproSteps", priority="false", azure_area="",
                  azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _finding(desc=ANGLED, lib="fastify"):
    return {
        "component": {"name": lib, "version": "1.0.0", "description": "A <fast> framework",
                      "dependencyType": "Direct", "dependencyFile": "package.json",
                      "localPath": "/app/node_modules/fastify",
                      "references": {"homePage": "https://fastify.io/?a=1&b=2"}},
        "dependencyContexts": [{"isDirect": True, "directRoots": [
            {"rootLibraryName": "app<1>", "rootLibraryVersion": "1.0.0"}]}],
        "vulnerability": {"name": "CVE-2021-23440", "description": desc, "score": 7.5,
                          "severity": "high", "publishDate": "2021-09-12T12:55:10Z",
                          "references": [{"url": "https://nvd.nist.gov/vuln/CVE-2021-23440",
                                          "advisory": True}]},
        "topFix": {"fixResolution": "4.0.1", "type": "UPGRADE_VERSION"},
        "findingInfo": {"status": "ACTIVE"},
    }


def _entry(finding=None):
    return {"library": "fastify", "kind": "vulnerability",
            "findings": [finding or _finding()], "licenses": [], "component": {}}


def _render(entry, conf=None):
    with mock.patch.object(core, "conf", conf or _conf()):
        return core.render_entry_v3("vulnerability", "fastify", entry, True)[0]["desc"]


# ------------------------------------------------------------------------------------- esc()

def test_angle_brackets_and_ampersands_are_escaped():
    assert core.esc("<2.0.1 & >3.0.0") == "&lt;2.0.1 &amp; &gt;3.0.0"


def test_quotes_are_escaped_so_a_value_cannot_break_out_of_an_attribute():
    """Every href in this tool is single-quoted, so an apostrophe in a URL or a name would end the
    attribute early and produce markup Azure then rewrites or drops."""
    escaped = core.esc("it's \"quoted\"")
    assert "'" not in escaped
    assert '"' not in escaped


def test_none_and_numbers_escape_without_raising():
    assert core.esc(None) == ""
    assert core.esc(7.5) == "7.5"


# ------------------------------------------------------------- nothing raw survives into a desc

def test_a_version_range_in_a_description_is_escaped_not_left_raw():
    desc = _render(_entry())
    assert "&lt;2.0.1, &gt;=3.0.0 &lt;4.0.1" in desc
    assert "<2.0.1" not in desc


def test_the_whole_sentence_survives_a_round_trip_through_azures_parser():
    """The point of the exercise: what Azure stores must still say what Mend said."""
    desc = _render(_entry())
    assert "A type confusion vulnerability can lead to RCE" in core.canonical_html(desc)


def test_the_epss_below_one_marker_is_escaped():
    finding = _finding()
    finding["threatAssessment"] = {"epssPercentage": 0.4}
    desc = _render(_entry(finding))
    assert "&lt;1%" in desc
    assert "<1%" not in desc


def test_library_metadata_and_parents_are_escaped():
    """Dependency mode no longer renders a Dependency Hierarchy list at all (Task 4,
    root-library-grouping): the root IS the top of the hierarchy, so its own parents are
    meaningless there. Per-CVE mode still renders one (library_block_v3(with_hierarchy=True)),
    so that is exercised here instead to keep the parents-are-escaped guarantee covered."""
    desc = _render(_entry())
    assert "A &lt;fast&gt; framework" in desc

    per_cve_desc = _render(_entry(), conf=_conf(dependency="false"))
    assert "app&lt;1&gt;@1.0.0" in per_cve_desc


def test_a_url_with_an_ampersand_is_escaped_inside_the_attribute():
    desc = _render(_entry())
    assert "https://fastify.io/?a=1&amp;b=2" in desc


def test_the_markup_this_tool_builds_is_not_escaped():
    """Only data is escaped. The structure has to stay real HTML or the description renders as
    visible tag soup."""
    desc = _render(_entry())
    for markup in ("<details>", "<summary>", "<table", "<td ", "<b>", "<a href="):
        assert markup in desc


def test_no_unescaped_data_angle_bracket_remains_anywhere_in_the_description():
    """Belt and braces: every "<" left in the output must open a real tag."""
    import re
    desc = _render(_entry())
    for match in re.finditer(r"<(?!/?[a-zA-Z])", desc):
        raise AssertionError(f"raw '<' from data at {match.start()}: {desc[match.start():][:60]!r}")


# ------------------------------------------------------------------ license and table escaping

def test_license_names_and_reference_files_are_escaped():
    html = core.build_license_html_v3(
        [{"name": "GPL-2.0+ <or later>", "url": "https://x/?a=1&b=2",
          "reference_file": "/src/a&b.xml"}], "No <GPL>", library_url="")
    assert "GPL-2.0+ &lt;or later&gt;" in html
    assert "a=1&amp;b=2" in html
    assert "/src/a&amp;b.xml" in html
    assert "No &lt;GPL&gt;" in html


def test_table_cells_and_headers_are_escaped():
    table = core.create_html_table([{"CVE": "CVE-1 <old>", "Fixed in": ">=4.0.1",
                                     "URL": "https://x/?a=1&b=2"}])
    assert "CVE-1 &lt;old&gt;" in table
    assert "&gt;=4.0.1" in table
    assert "a=1&amp;b=2" in table


def test_a_bulleted_list_escapes_its_items():
    assert core.generate_html_bulleted_list(["a<b>c"]) == "<ul>\n  <li>a&lt;b&gt;c</li>\n</ul>"


def test_an_expandable_section_escapes_nothing_itself():
    """Its summary is markup at some call sites ("<b>License Details</b>") and data at others (a
    CVE name), so it cannot escape blindly -- escaping happens at the call sites that pass data.
    Its detail is HTML this tool already built and must never be escaped twice."""
    section = core.generate_expandable_section("<b>License Details</b>", "<b>kept</b>")
    assert "<b>License Details</b>" in section
    assert "<b>kept</b>" in section


def test_a_summary_that_carries_data_is_escaped_by_its_call_site():
    """The per-CVE and per-library summaries are data, and they are escaped before they get
    there."""
    finding = _finding()
    finding["vulnerability"]["name"] = "CVE-1 <old>"
    desc = _render(_entry(finding))
    assert "CVE-1 &lt;old&gt;" in desc
    assert "<summary>CVE-1 <old>" not in desc
