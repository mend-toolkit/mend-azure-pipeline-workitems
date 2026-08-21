import re
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync import enrichment as en


def test_url_must_remain_the_last_row_key():
    """create_html_table drops the final cell by position, assuming URL is last.

    The enrichment columns are gated on `enrich_on` (MEND_ENRICHMENT), so the row is built by
    mutating a `row` dict rather than a single dict literal. This parses the ORDER OF
    ASSIGNMENTS made to `row`, not a literal's keys. This is a guard test, not a feature
    test: if someone appends a column after URL, the column vanishes from every work item
    silently. Failing loudly here is the point.
    """
    src = core.__file__
    with open(src, encoding="utf-8") as fh:
        body = fh.read()
    start = body.index("row = {")
    end = body.index("table_data.append(row)", start)
    block = body[start:end]
    keys = []
    for line in block.splitlines():
        m = re.search(r'"([A-Za-z ]+)":', line) or re.search(r'row\["([A-Za-z ]+)"\]\s*=', line)
        if m:
            keys.append(m.group(1))
    assert keys[-1] == "URL", f"URL must be the last key assigned to row, got {keys}"
    assert keys[-2] == "Reachability", f"Reachability must be assigned immediately before URL, got {keys}"
    assert "EPSS" in keys and "Exploit" in keys


def test_no_enrichment_keys_are_added_when_the_flag_is_off():
    # MEND_ENRICHMENT defaults to false. Existing users must see a byte-identical work item
    # -- not three columns of "-". The README promises exactly this, so EPSS/Exploit/
    # Reachability must never be written to `row` except behind an `if enrich_on:` guard.
    # There is no create_wi test harness to drive this behaviourally (none exists in this
    # suite), so this asserts on the source structure instead.
    src = core.__file__
    with open(src, encoding="utf-8") as fh:
        body = fh.read()
    start = body.index("row = {")
    end = body.index("table_data.append(row)", start)
    block = body[start:end]

    literal_dict = block[:block.index("}")]
    for key in ("EPSS", "Exploit", "Reachability"):
        assert f'"{key}"' not in literal_dict, (
            f'"{key}" must not be an unconditional row key, got literal {literal_dict!r}')

    epss_exploit_guarded = re.search(
        r'if enrich_on:\s*\n\s*row\["EPSS"\]\s*=\s*format_epss\(policy_el\)\s*\n'
        r'\s*row\["Exploit"\]\s*=\s*format_exploit\(policy_el\)', block)
    assert epss_exploit_guarded, "EPSS and Exploit must be assigned together inside 'if enrich_on:'"

    reachability_guarded = re.search(
        r'if enrich_on:\s*\n\s*row\["Reachability"\]\s*=\s*format_reachability\(policy_el\)', block)
    assert reachability_guarded, "Reachability must be assigned inside its own 'if enrich_on:'"

    # Only these two guards should exist in the row-building block -- confirms Dependency,
    # Type, Fixed in and URL are unconditional, not gated.
    assert block.count("if enrich_on:") == 2, \
        f"expected exactly 2 'if enrich_on:' guards in the row block, got {block.count('if enrich_on:')}"


def test_vul_data_enrich_html_is_empty_string_when_flag_is_off():
    """Both MEND_DEPENDENCY branches splice `enrich_html` into vul_data (the CVE's
    expandable detail section when MEND_DEPENDENCY=true, the flat per-CVE description when
    it's false). test_no_enrichment_keys_are_added_when_the_flag_is_off already covers the
    table-row gating; this is the other half of the same invariant -- with the flag off,
    the description must be byte-identical to before this feature -- for the two vul_data
    sites. There is no create_wi test harness to drive this behaviourally, so this asserts
    on the source structure, same style as test_url_must_remain_the_last_row_key.
    """
    src = core.__file__
    with open(src, encoding="utf-8") as fh:
        body = fh.read()

    guarded_sites = re.findall(
        r'enrich_html\s*=\s*\(f"<br><b>Reachability:</b>.*?"\)\s*\\?\s*\n\s*if enrich_on else ""',
        body, re.DOTALL)
    assert len(guarded_sites) == 2, (
        f"expected exactly 2 'enrich_html = (...) if enrich_on else \"\"' sites, one per "
        f"MEND_DEPENDENCY branch, got {len(guarded_sites)}")

    spliced = body.count("enrich_html + \\")
    assert spliced == 2, (
        f"expected both vul_data sites to splice the guarded enrich_html variable, "
        f"got {spliced}")


def test_decoration_failure_cannot_cost_work_items():
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    # Patch on `core`, not on `enrichment`: core binds the name at import time, so patching
    # the source module would leave core's reference untouched and this test would pass
    # while testing nothing.
    with mock.patch.object(core, "decorate_policy_violations", side_effect=TypeError("boom")):
        assert core.safe_decorate(libs, {}) is None


def test_decoration_failure_after_the_call_also_cannot_cost_work_items():
    # safe_decorate's whole body must be guarded, not just the decorate_policy_violations
    # call: an arity change in its return value must not raise into create_wi either.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with mock.patch.object(core, "decorate_policy_violations", return_value=(1,)):  # wrong arity
        assert core.safe_decorate(libs, {}) is None


def test_safe_decorate_warns_only_when_candidates_matched_nothing(caplog):
    # The alerts index carries every open alert in the project while candidates is only
    # this window's policy violations, so warning on "0 of N findings" would fire on most
    # projects every run and train operators to ignore the one signal that detects a
    # broken join.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, {})
    assert any("matched" in r.message for r in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING"):
        core.safe_decorate([], {("CVE-1", "lib-a"): {}})
    assert not caplog.records


def test_a_normal_epss_score_does_not_warn(caplog):
    """The EPSS unit question is settled: epssPercentage is 0-100, confirmed against live
    Mend data 2026-08-19.

    The old `> 1` warning existed only to detect the unit being a percentage. Now that it
    IS a percentage, values above 1 are ordinary — every genuinely exploited CVE has one —
    so a warning there would fire constantly and say something false.
    """
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, {("CVE-1", "lib-a"): {"epss": 92.4}})
    assert not [r for r in caplog.records if "100x" in r.message]


def test_format_reachability_ignores_a_non_string_leaf():
    # dict.get() raises TypeError: unhashable type on a dict/list key. _get only guarantees
    # the CONTAINER is a dict, never the leaf type, and this formatter is called unguarded
    # from inside create_wi -- an exception here would silently drop every work item for
    # the project while the run still reported success.
    assert en.format_reachability({"reachability": {"unexpected": "object"}}) == en.NO_DATA
    assert en.format_reachability({"reachability": ["unexpected"]}) == en.NO_DATA


def test_format_exploit_ignores_a_non_string_leaf():
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": {"unexpected": "object"}}}}
    ) == en.NO_DATA
    assert en.format_exploit(
        {"vulnerability": {"threatAssessment": {"exploitCodeMaturity": ["unexpected"]}}}
    ) == en.NO_DATA
