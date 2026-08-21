import json
import logging
from unittest import mock

import pytest

from mend_azure_wi_sync import core


def test_fetch_project_alerts_asks_1_4_for_this_project_s_vulnerability_alerts():
    """One call per project on the transport every other 1.4 call already uses. The alert
    carries projectToken itself, so nothing has to resolve a 3.0 uuid first."""
    alert = {"vulnerability": {"name": "CVE-1",
                               "threatAssessment": {"epssPercentage": 2.5,
                                                    "exploitCodeMaturity": "HIGH"}},
             "reachabilityInfo": {"reachable": True, "analyzed": True},
             "library": {"keyUuid": "lib-a"}}
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="uk", ws_org_token="ot",
                                                        enrichment="true")), \
         mock.patch.object(core, "call_ws_api",
                           return_value=json.dumps({"alerts": [alert]})) as api:
        index = core.fetch_project_alerts("tok-1")
    body = json.loads(api.call_args.kwargs["data"])
    assert body["requestType"] == "getProjectAlertsByType"
    assert body["projectToken"] == "tok-1"
    assert body["alertType"] == "SECURITY_VULNERABILITY"
    assert index == {("CVE-1", "lib-a"): {"reachability": "REACHABLE", "epss": 2.5,
                                          "maturity": "HIGH"}}


def test_fetch_project_alerts_makes_exactly_one_call():
    """API 1.4 does not paginate, so the 3.0 cursor loop and its 20-page cap are gone. A
    reintroduced loop here would be a silent per-project cost multiplier."""
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "call_ws_api",
                           return_value=json.dumps({"alerts": []})) as api:
        assert core.fetch_project_alerts("tok-1") == {}
    assert api.call_count == 1


@pytest.mark.parametrize("payload", ['{"errorCode": 5001}', "{}", '{"alerts": "nope"}',
                                     "not json", ""])
def test_a_failed_or_odd_alerts_response_yields_an_empty_index(payload):
    """Display-only data must never cost a Work Item, so every failure path is {}."""
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "call_ws_api", return_value=payload):
        assert core.fetch_project_alerts("tok-1") == {}


def test_a_wholesale_alerts_failure_warns_exactly_once(caplog):
    """A TOTAL enrichment failure must be loud, and loud exactly once.

    This is the gap the deleted prepare_enrichment used to cover. create_wi only calls
    safe_decorate when the index is non-empty, and safe_decorate owns the only other
    enrichment warning ("matched 0 of N candidate finding(s)"), so a user key that cannot read
    alerts would render "-" in all three columns for all ~107 projects while the log said
    nothing but "Enrichment: on". Once-per-run, not once-per-project: the failure is
    identical for every project, and 107 identical lines is the same as none.
    """
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "call_ws_api", return_value='{"errorCode": 5001}'):
        with caplog.at_level(logging.WARNING):
            assert core.fetch_project_alerts("tok-1") == {}
            assert core.fetch_project_alerts("tok-2") == {}
    hits = [r for r in caplog.records if "Could not read Mend alerts" in r.message]
    assert len(hits) == 1, [r.message for r in caplog.records]
    # The message must tell the operator what they will SEE, not just that a call failed.
    assert "blank ('-')" in hits[0].message
    assert core.ALERTS_WARNED is True


def test_a_successful_alerts_fetch_warns_about_nothing(caplog):
    with mock.patch.object(core, "conf", mock.MagicMock(ws_user_key="uk", ws_org_token="ot")), \
         mock.patch.object(core, "call_ws_api", return_value=json.dumps({"alerts": []})):
        with caplog.at_level(logging.WARNING):
            assert core.fetch_project_alerts("tok-1") == {}
    assert not [r for r in caplog.records if "Could not read Mend alerts" in r.message]
    assert core.ALERTS_WARNED is False


def test_enrich_project_needs_no_resolution_step():
    """The whole point of #14: no uuid map, no name join, no 2.0 login. If enrichment is on,
    a project token is all that is needed."""
    with mock.patch.object(core, "conf", mock.MagicMock(enrichment="true")), \
         mock.patch.object(core, "fetch_project_alerts", return_value={("CVE-1", "lib-a"): {}}) as f:
        assert core.enrich_project("tok-1") == {("CVE-1", "lib-a"): {}}
    f.assert_called_once_with("tok-1")


def test_enrich_project_is_empty_when_enrichment_is_off():
    with mock.patch.object(core, "conf", mock.MagicMock(enrichment="false")), \
         mock.patch.object(core, "fetch_project_alerts") as f:
        assert core.enrich_project("tok-1") == {}
    f.assert_not_called()


def test_a_raising_fetch_never_reaches_create_wi():
    with mock.patch.object(core, "conf", mock.MagicMock(enrichment="true")), \
         mock.patch.object(core, "fetch_project_alerts", side_effect=Exception("boom")):
        assert core.enrich_project("tok-1") == {}


def test_the_2_0_and_3_0_transports_are_gone():
    """Guards the deletion. These names existing again means the consolidation regressed."""
    for gone in ("call_ws_api_v3", "fetch_project_enrichment", "resolve_project_uuids",
                 "prepare_enrichment", "project_uuid_map", "enrichment_disabled",
                 "ENRICHMENT_PAGE_LIMIT", "ENRICHMENT_MAX_PAGES"):
        assert not hasattr(core, gone), f"{gone} should have been deleted"
