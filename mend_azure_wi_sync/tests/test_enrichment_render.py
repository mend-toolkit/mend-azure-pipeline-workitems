from unittest import mock

from mend_azure_wi_sync import core


def test_url_must_remain_the_last_table_key():
    """create_html_table drops the final cell by position, assuming URL is last.

    This is a guard test, not a feature test: if someone appends a column after URL, the
    column vanishes from every work item silently. Failing loudly here is the point.
    """
    src = core.__file__
    with open(src, encoding="utf-8") as fh:
        body = fh.read()
    start = body.index("table_data.append({")
    block = body[start:body.index("})", start)]
    keys = [line.split('"')[1] for line in block.splitlines() if '":' in line]
    assert keys[-1] == "URL", f"URL must be the last table_data key, got {keys}"
    assert keys[-2] == "Reachability", f"Reachability must precede URL, got {keys}"
    assert "EPSS" in keys and "Exploit" in keys


def test_decoration_failure_cannot_cost_work_items():
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    # Patch on `core`, not on `enrichment`: core binds the name at import time, so patching
    # the source module would leave core's reference untouched and this test would pass
    # while testing nothing.
    with mock.patch.object(core, "decorate_policy_violations", side_effect=TypeError("boom")):
        assert core.safe_decorate(libs, {}) is None


def test_safe_decorate_warns_only_when_candidates_matched_nothing(caplog):
    # 3.0 returns every finding in the project while 1.4 returns only this window's policy
    # violations, so warning on "0 of N findings" would fire on most projects every run and
    # train operators to ignore the one signal that detects a broken join.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, {})
    assert any("matched" in r.message for r in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING"):
        core.safe_decorate([], {("CVE-1", "lib-a"): {}})
    assert not caplog.records


def test_safe_decorate_warns_once_when_epss_exceeds_one(caplog):
    # The 0-1 reading is a decision, not a verified fact. A value above 1 is the only
    # evidence the unit is a percentage, in which case every figure is 100x too high.
    libs = [{"library": {"keyUuid": "lib-a"},
             "policyViolations": [{"vulnerability": {"name": "CVE-1"}}]}]
    index = {("CVE-1", "lib-a"): {"epss": 5.0}}
    core.epss_unit_warned = False
    with caplog.at_level("WARNING"):
        core.safe_decorate(libs, index)
        core.safe_decorate(libs, index)
    assert len([r for r in caplog.records if "100x" in r.message]) == 1
