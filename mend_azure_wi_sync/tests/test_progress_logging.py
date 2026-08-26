"""Progress logging for a long-running sync.

A run with routing on and no MEND_AZUREPROJECT skips the startup work item type probe, so
for a large project the pipeline printed nothing between "Selection mode" and the first
project's summary -- which reads as a stalled job. These tests pin the three lines that make
progress visible (a project header carrying the total, a periodic counter, and a summary
split by work item kind) and keep the per-item chatter at DEBUG.
"""

import logging
from unittest import mock

from mend_azure_wi_sync import core


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false",
                  reponame="", routing="false", description="Description", priority="false",
                  azure_area="", azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


def _finding(cve="CVE-2020-8203", score=7.4, lib="lodash"):
    return {
        "component": {"name": lib, "version": "4.17.15", "dependencyType": "Direct",
                      "references": {"homePage": "https://lodash.com/"}},
        "dependencyContexts": [{"isDirect": True, "directRoots": [
            {"rootLibraryName": "app", "rootLibraryVersion": "1.0.0"}]}],
        "vulnerability": {"name": cve, "description": "Prototype pollution.", "score": score,
                          "severity": "high", "publishDate": "2020-07-15", "references": []},
        "topFix": {"fixResolution": "Upgrade to 4.17.19"},
        "threatAssessment": {"epssPercentage": 12.5, "exploitCodeMaturity": "POC"},
        "reachability": "REACHABLE",
        "findingInfo": {"status": "ACTIVE"},
    }


def _vuln_entry(lib="lodash"):
    return {"library": lib, "kind": "vulnerability", "findings": [_finding(lib=lib)],
            "licenses": []}


def _license_entry(lib="lodash"):
    return {"library": lib, "kind": "license",
            "findings": [{"findingType": "LEGAL", "originName": lib,
                          "name": "[Legal] No copyleft", "uuid": "v-1"}],
            "licenses": [{"name": "GPL-3.0", "url": "https://spdx.org/gpl",
                          "reference_file": "pom.xml"}]}


_PROJECT = {"uuid": "p-1", "name": "Proj", "application_name": "Prod"}


def _run(desired, caplog, level="INFO"):
    """Drive create_wi_v3 with Azure doubled. Returns the emitted log messages."""
    azure = mock.MagicMock(return_value=({"id": 42, "fields": {"System.State": "New"}}, 0))
    caplog.clear()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "call_azure_api", azure), \
         mock.patch.object(core, "exist_wis", []), \
         mock.patch.object(core, "updated_wi", []), \
         caplog.at_level(level, logger=core.logger.name):
        core.create_wi_v3(_PROJECT, desired, [], "Task")
    return [r.getMessage() for r in caplog.records]


def _many(n, kind="vulnerability"):
    build = _vuln_entry if kind == "vulnerability" else _license_entry
    return {(kind, f"lib-{i}"): build(f"lib-{i}") for i in range(n)}


# --- the project header ----------------------------------------------------------------------

def test_project_header_names_the_project_and_the_total_before_any_work(caplog):
    """Without this line a big project is silent until every one of its items is written."""
    messages = _run(_many(3), caplog)
    header = [m for m in messages if "Processing" in m and "Prod/Proj" in m]
    assert header, messages
    assert "3 total" in header[0]


def test_project_header_is_logged_before_the_first_work_item(caplog):
    messages = _run(_many(3), caplog)
    header_at = next(i for i, m in enumerate(messages) if "Processing" in m)
    summary_at = next(i for i, m in enumerate(messages) if "processed" in m and "total" not in m)
    assert header_at < summary_at


# --- the periodic counter --------------------------------------------------------------------

def test_progress_is_logged_every_twenty_items(caplog):
    messages = _run(_many(45), caplog)
    progress = [m for m in messages if "/45 processed" in m]
    assert [p.split(":")[-1].strip() for p in progress] == \
        ["20/45 processed", "40/45 processed"]


def test_no_progress_line_for_a_project_under_the_threshold(caplog):
    """Twenty is the anti-spam threshold: a small project should say nothing in between."""
    messages = _run(_many(7), caplog)
    assert not [m for m in messages if "/7 processed" in m]


def test_the_final_item_does_not_get_its_own_progress_line(caplog):
    """A project of exactly 20 would otherwise log '20/20 processed' immediately before the
    summary that says the same thing."""
    messages = _run(_many(20), caplog)
    assert not [m for m in messages if "20/20 processed" in m]


# --- the summary, split by kind ---------------------------------------------------------------

def test_summary_splits_vulnerability_from_license(caplog):
    desired = {}
    desired.update({("vulnerability", f"lib-{i}"): _vuln_entry(f"lib-{i}") for i in range(3)})
    desired.update({("license", f"lic-{i}"): _license_entry(f"lic-{i}") for i in range(2)})
    messages = _run(desired, caplog)
    joined = "\n".join(messages)
    assert "Vulnerability:" in joined
    assert "License:" in joined
    vuln_line = next(m for m in messages if "Vulnerability:" in m)
    lic_line = next(m for m in messages if "License:" in m)
    assert "3 created" in vuln_line, vuln_line
    assert "2 created" in lic_line, lic_line


def test_summary_omits_a_kind_the_project_has_none_of(caplog):
    """A project with no license work items should not print a row of zeroes for them."""
    messages = _run(_many(2), caplog)
    assert not [m for m in messages if "License:" in m]


# --- noise kept out of INFO --------------------------------------------------------------------

def test_per_item_creation_is_not_logged_at_info(caplog):
    """'Task 42 created', once per work item, is what made the old logs unreadable."""
    messages = _run(_many(3), caplog, level="INFO")
    assert not [m for m in messages if m.startswith("Task 42")], messages


def test_per_item_creation_is_still_available_at_debug(caplog):
    messages = _run(_many(3), caplog, level="DEBUG")
    assert [m for m in messages if m.startswith("Task 42")], messages


# --- no funcName:lineno in the message ---------------------------------------------------------

def test_messages_carry_no_function_and_line_prefix(caplog):
    """[create_wi_v3:2091] belongs to the DEBUG log format, not to the message text."""
    messages = _run(_many(3), caplog)
    assert not [m for m in messages if m.startswith("[create_wi_v3:")], messages


# --- the read announcement ---------------------------------------------------------------------

def _sync_one(caplog, position=""):
    """Drive sync_project_v3 with the Mend read and both halves doubled."""
    caplog.clear()
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "fetch_v3_desired", return_value=({}, True)), \
         mock.patch.object(core, "create_wi_v3", return_value=(0, 0, 0)), \
         mock.patch.object(core, "reconcile_project", return_value=(0, 0, 0, 0, 0)), \
         mock.patch.object(core, "synced_projects", []), \
         caplog.at_level(logging.INFO, logger=core.logger.name):
        core.sync_project_v3({"uuid": "p-1", "name": "Proj", "application_name": "Prod"},
                             7.0, [], "Task", position=position)
    return [r.getMessage() for r in caplog.records]


def test_the_mend_read_is_announced_before_it_starts(caplog):
    """fetch_v3_desired is the longest silence in a run. Announcing it after the fact is what
    made a large project look like a stalled pipeline."""
    messages = _sync_one(caplog)
    assert any("Reading Prod/Proj from Mend" in m for m in messages), messages


def test_the_read_announcement_carries_the_position_through_the_run(caplog):
    messages = _sync_one(caplog, position="3/47")
    assert any(m.startswith("[3/47] Reading Prod/Proj") for m in messages), messages


def test_the_read_announcement_omits_an_empty_position(caplog):
    """No caller should print a bare '[] Reading ...'."""
    messages = _sync_one(caplog)
    assert not [m for m in messages if m.startswith("[]")], messages
