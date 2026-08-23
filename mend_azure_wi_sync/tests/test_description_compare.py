"""Comparing a description Azure DevOps has stored against the one this run would write.

Confirmed live: System.Description is the field that differs on every work item, every run, so
nothing is ever skipped. Azure DevOps does not store HTML byte-for-byte as sent -- it sanitises
and reformats it -- so a raw string compare of that field can NEVER match, no matter what the
content is.

The rule here: compare what the description SAYS, not how Azure chose to mark it up. Canonical
form is the visible text plus every URL, in order. That keeps the comparison safe in the
direction that matters -- any change to text or to a link still reads as a change, because both
are inside the canonical form -- while markup Azure rewrote on its own does not.

Anything that cannot be canonicalised falls back to the raw compare, which reports a difference.
"""

from mend_azure_wi_sync import core


def _ops(value):
    return [{"op": "replace", "path": "/fields/System.Description", "value": value}]


# --------------------------------------------------------------------------- canonical_html

def test_tags_are_dropped_and_text_survives():
    assert core.canonical_html("<b>Library - </b>lodash") == core.canonical_html("Library - lodash")


def test_whitespace_between_tags_is_collapsed():
    a = "<p>one</p>\n\n  <p>two</p>"
    b = "<p>one</p><p>two</p>"
    assert core.canonical_html(a) == core.canonical_html(b)


def test_a_wrapper_azure_adds_does_not_count_as_a_change():
    inner = "<details><summary><b>License Details</b></summary><p>MIT</p></details>"
    assert core.canonical_html(inner) == core.canonical_html(f"<div>{inner}</div>")


def test_entities_are_unescaped_so_encoding_differences_collapse():
    assert core.canonical_html("A &amp; B") == core.canonical_html("A & B")
    assert core.canonical_html("2&nbsp;vulnerabilities") == core.canonical_html("2 vulnerabilities")


def test_urls_are_part_of_the_canonical_form():
    """Markup is ignored, but a link's target is content -- changing where the operator lands is
    a real change and must not be swallowed."""
    a = "<a href='https://nvd.nist.gov/vuln/CVE-2020-8203'>CVE-2020-8203</a>"
    b = "<a href='https://example.com/other'>CVE-2020-8203</a>"
    assert core.canonical_html(a) != core.canonical_html(b)


def test_quote_style_and_attribute_order_are_not_content():
    a = '<a href="https://x/" target="_blank">x</a>'
    b = "<a target='_blank' href='https://x/'>x</a>"
    assert core.canonical_html(a) == core.canonical_html(b)


def test_a_real_text_change_is_still_a_change():
    assert core.canonical_html("<b>CVSS 3 Score Details </b>(7.4)") != \
        core.canonical_html("<b>CVSS 3 Score Details </b>(9.8)")


def test_none_and_non_strings_canonicalise_without_raising():
    assert core.canonical_html(None) == ""
    assert core.canonical_html(7.4) == "7.4"


# ------------------------------------------------------------------- wi_content_diff behaviour

def test_a_description_azure_reformatted_is_no_longer_reported_as_changed():
    sent = "<b>Library - </b>lodash<br><b>Path to library:</b>/app/node_modules/lodash"
    stored = ("<div><b>Library - </b>lodash<br />\n"
              "<b>Path to library:</b>/app/node_modules/lodash</div>")
    assert core.wi_content_diff(_ops(sent), {"System.Description": stored}) == []


def test_a_description_whose_content_changed_is_still_reported():
    sent = "<b>CVSS 3 Score Details </b>(9.8)"
    stored = "<div><b>CVSS 3 Score Details </b>(7.4)</div>"
    assert core.wi_content_diff(_ops(sent), {"System.Description": stored}) \
        == ["System.Description"]


def test_a_description_whose_only_change_is_a_link_target_is_still_reported():
    sent = "<a href='https://nvd.nist.gov/vuln/CVE-2020-8203'>CVE-2020-8203</a>"
    stored = "<div><a href='https://example.com/stale'>CVE-2020-8203</a></div>"
    assert core.wi_content_diff(_ops(sent), {"System.Description": stored}) \
        == ["System.Description"]


def test_the_markup_tolerance_applies_to_any_html_target_field():
    """MEND_DESCRIPTION can point the description at ReproSteps or a custom HTML field, and Azure
    sanitises those the same way."""
    for field in ("Microsoft.VSTS.TCM.ReproSteps", "Custom.MendDetails"):
        ops = [{"op": "replace", "path": f"/fields/{field}", "value": "<b>x</b>y"}]
        assert core.wi_content_diff(ops, {field: "<div><b>x</b>y</div>"}) == []


def test_a_plain_text_field_is_still_compared_exactly():
    """The title is the identity key. No normalisation may touch it -- two titles differing only
    in whitespace are two different work items to classify_title."""
    ops = [{"op": "replace", "path": "/fields/System.Title", "value": "lodash: 2 vulnerabilities"}]
    assert core.wi_content_diff(ops, {"System.Title": "lodash:  2  vulnerabilities"}) \
        == ["System.Title"]


def test_an_html_field_that_azure_never_returned_is_still_absent_not_equal():
    ops = _ops("<b>x</b>")
    assert core.wi_content_diff(ops, {"System.Title": "t"}) == ["System.Description (absent)"]


def test_an_emptied_description_is_still_a_change():
    assert core.wi_content_diff(_ops("<b>x</b>"), {"System.Description": ""}) \
        == ["System.Description"]
    assert core.wi_content_diff(_ops(""), {"System.Description": "<div>x</div>"}) \
        == ["System.Description"]
