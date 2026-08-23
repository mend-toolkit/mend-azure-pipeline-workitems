"""A description that says the same thing must render the same way, run after run.

Two causes of a description differing every run, both in this tool's own output rather than in
Mend's data:

  1. EMPTY ANCHORS. vuln_section_v3 renders the "Origin:" line as <a href='...'></a> -- a link
     with a URL and no text at all (inherited from the 1.4 shape). Azure DevOps sanitises stored
     HTML and drops empty elements, so the href never comes back, and a canonical form that counts
     URLs would report a difference forever. Its URL is invisible to an operator, so it is not
     content.

  2. UNSTABLE ORDER. Rows, parents and licenses were emitted in whatever order the Mend API
     happened to return them, with ties in the CVE sort falling through to that order. Two
     findings with equal scores could swap places between runs and rewrite every work item in the
     project for no reason.

Neither is a Mend data problem, and neither is fixed by comparing more loosely: a description has
to be deterministic before "did it change" is even a meaningful question.
"""

from mend_azure_wi_sync import core, source3


# --------------------------------------------------------------- empty anchors are not content

def test_an_empty_anchors_url_is_not_part_of_the_canonical_form():
    assert core.canonical_html("<b>Origin:</b> <a href='https://x/'></a>") == \
        core.canonical_html("<b>Origin:</b> ")


def test_azure_dropping_an_empty_anchor_is_not_reported_as_a_change():
    sent = "<b>Suggested Fix:</b> UPGRADE_VERSION<br><b>Origin:</b> <a href='https://x/'></a>"
    stored = "<div><b>Suggested Fix:</b> UPGRADE_VERSION<br /><b>Origin:</b> </div>"
    ops = [{"op": "replace", "path": "/fields/System.Description", "value": sent}]
    assert core.wi_content_diff(ops, {"System.Description": stored}) == []


def test_a_link_with_visible_text_still_counts_as_content():
    """Only EMPTY anchors are discounted. A link an operator can actually click is content, and
    changing its target is still a change."""
    a = "<a href='https://nvd.nist.gov/vuln/CVE-1'>CVE-1</a>"
    b = "<a href='https://elsewhere/'>CVE-1</a>"
    assert core.canonical_html(a) != core.canonical_html(b)


def test_an_anchor_holding_only_whitespace_counts_as_empty():
    assert core.canonical_html("<a href='https://x/'>  </a>") == core.canonical_html("")


# ------------------------------------------------------------------------- deterministic order

def _finding(cve, score, lib="lodash", parents=()):
    return {"component": {"name": lib},
            "dependencyContexts": [{"directRoots": [
                {"rootLibraryName": p, "rootLibraryVersion": "1.0.0"} for p in parents]}],
            "vulnerability": {"name": cve, "score": score}}


def test_equal_scores_are_ordered_by_cve_name_not_by_api_order():
    one = [_finding("CVE-2021-0002", 7.5), _finding("CVE-2021-0001", 7.5)]
    other = list(reversed(one))
    assert [r["name"] for r in source3._vulnerabilities(one)] == \
           [r["name"] for r in source3._vulnerabilities(other)] == \
           ["CVE-2021-0001", "CVE-2021-0002"]


def test_scores_still_lead_and_unscored_findings_still_come_last():
    findings = [_finding("CVE-B", ""), _finding("CVE-A", 4.0), _finding("CVE-C", 9.8)]
    assert [r["name"] for r in source3._vulnerabilities(findings)] == \
        ["CVE-C", "CVE-A", "CVE-B"]


def test_unscored_findings_are_ordered_among_themselves_by_name():
    findings = [_finding("CVE-Z", ""), _finding("CVE-A", None)]
    assert [r["name"] for r in source3._vulnerabilities(findings)] == ["CVE-A", "CVE-Z"]


def test_the_dependency_hierarchy_is_ordered_not_api_ordered():
    one = source3._parents([_finding("CVE-1", 7.0, parents=("zeta", "alpha"))])
    other = source3._parents([_finding("CVE-1", 7.0, parents=("alpha", "zeta"))])
    assert one == other == ["alpha@1.0.0", "zeta@1.0.0"]


def test_licenses_are_ordered_by_name_after_a_merge():
    primary = {"lib": [{"name": "MIT", "url": "", "reference_file": ""},
                       {"name": "Apache-2.0", "url": "", "reference_file": ""}]}
    fallback = {"lib": [{"name": "GPL-3.0", "url": "u", "reference_file": ""}]}
    merged = source3.merge_license_index(primary, fallback)
    assert [lic["name"] for lic in merged["lib"]] == ["Apache-2.0", "GPL-3.0", "MIT"]


def test_two_runs_over_reshuffled_api_output_render_an_identical_description():
    """The end-to-end guarantee: same facts in a different order from Mend, same description --
    so the unchanged-check has something stable to compare."""
    from unittest import mock
    findings = [_finding("CVE-2021-0002", 7.5, parents=("zeta",)),
                _finding("CVE-2021-0001", 7.5, parents=("alpha",))]
    conf = mock.MagicMock(dependency="true")
    descs = []
    for ordering in (findings, list(reversed(findings))):
        entry = {"library": "lodash", "kind": "vulnerability", "findings": ordering,
                 "licenses": [], "component": {}}
        with mock.patch.object(core, "conf", conf):
            descs.append(core.render_entry_v3("vulnerability", "lodash", entry, False)[0]["desc"])
    assert descs[0] == descs[1]


# ------------------------------------------------------- saying WHERE two descriptions diverge

def test_the_divergence_snippet_points_at_the_first_difference():
    sent = "Library - lodash Path to library: /app/node_modules/lodash CVSS 3 Score (9.8)"
    stored = "Library - lodash Path to library: /app/node_modules/lodash CVSS 3 Score (7.4)"
    snippet = core.canonical_divergence(sent, stored)
    assert "9.8" in snippet
    assert "7.4" in snippet
    # the shared prefix is not repeated in full
    assert "Library - lodash Path" not in snippet


def test_identical_values_have_no_divergence():
    assert core.canonical_divergence("<b>x</b>y", "<div><b>x</b>y</div>") == ""


def test_a_divergence_at_the_very_start_is_handled():
    assert "aaa" in core.canonical_divergence("aaa", "bbb")


def test_a_value_that_is_only_longer_reports_the_extra_tail():
    snippet = core.canonical_divergence("one two three", "one two")
    assert "three" in snippet


def test_the_snippet_is_bounded_so_a_log_line_stays_readable():
    a = "x" * 200 + "A" + "y" * 200
    b = "x" * 200 + "B" + "y" * 200
    assert len(core.canonical_divergence(a, b)) < 200


# ------------------------------------------- a raw "<" in CONTENT is not the start of a tag
#
# Both live divergences came from this, not from Mend data:
#
#   ReproSteps at char 497: sent 'Not Defined path-to-regexp...'  | azure '<1% Not Defined path...'
#   ReproSteps at char 744: sent 'Publish Date: 2022-03-17...'    | azure '<=1.2.5 is vulnerable...'
#
# enrichment.EPSS_BELOW_ONE is the literal "<1%", and Mend vulnerability descriptions say things
# like "<=1.2.5 is vulnerable to Prototype Pollution". Azure stores those escaped ("&lt;1%"), this
# tool sends them raw, and a "<[^>]*>" tag pattern eats from the raw "<" to the NEXT ">" -- taking
# real text with it, and a different amount on each side. Permanent mismatch on every work item
# carrying an EPSS score or a description with a version range.


def test_a_bare_less_than_in_content_is_not_treated_as_a_tag():
    assert core.canonical_html("<b>EPSS:</b> <1%") == "EPSS: <1%"


def test_the_epss_below_one_marker_round_trips_against_azures_escaped_copy():
    sent = "<b>EPSS:</b> <1%<b>Exploit Code Maturity:</b> Not Defined"
    stored = "<div><b>EPSS:</b> &lt;1%<b>Exploit Code Maturity:</b> Not Defined</div>"
    assert core.canonical_html(sent) == core.canonical_html(stored)


def test_a_version_range_in_a_vulnerability_description_round_trips():
    sent = "<b>Vulnerability Details:</b> <=1.2.5 is vulnerable to Prototype Pollution"
    stored = "<div><b>Vulnerability Details:</b> &lt;=1.2.5 is vulnerable to Prototype Pollution</div>"
    assert core.wi_content_diff(
        [{"op": "replace", "path": "/fields/Microsoft.VSTS.TCM.ReproSteps", "value": sent}],
        {"Microsoft.VSTS.TCM.ReproSteps": stored}) == []


def test_real_tags_are_still_stripped():
    assert core.canonical_html("<div><b>x</b><br /><IMG src='u'></div>") == "x\x00u"


def test_an_html_comment_is_still_stripped():
    assert core.canonical_html("a<!-- note -->b") == "a b".replace("  ", " ")


def test_a_less_than_followed_by_a_letter_is_still_a_tag_not_content():
    """The ambiguity is unavoidable: "<b>" is a tag and "<1%" is not, and the rule is what
    follows the "<". A stray "<b" in prose would be read as markup -- accepted, because the
    alternative is failing to strip real markup."""
    assert core.canonical_html("<b>bold</b>") == "bold"


def test_escaped_and_real_markup_still_do_not_collapse():
    """Preserved from the original design: this direction reports a change, which is the safe way
    to be wrong."""
    assert core.canonical_html("&lt;b&gt;x&lt;/b&gt;") != core.canonical_html("<b>x</b>")
