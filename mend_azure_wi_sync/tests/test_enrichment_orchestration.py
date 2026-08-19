from unittest import mock

import pytest

from mend_azure_wi_sync import core


@pytest.fixture(autouse=True)
def _reset_state():
    core.enrichment_disabled = False
    core.project_uuid_map = {}
    yield
    core.enrichment_disabled = False
    core.project_uuid_map = {}


def _on():
    return mock.MagicMock(enrichment="true")


def test_disabled_flag_means_no_calls_at_all():
    with mock.patch.object(core, "conf", mock.MagicMock(enrichment="false")), \
         mock.patch.object(core, "resolve_project_uuids") as resolve, \
         mock.patch.object(core, "fetch_project_enrichment") as fetch:
        core.prepare_enrichment(["tok-1"])
        assert core.enrich_project("tok-1") == {}
    resolve.assert_not_called()
    fetch.assert_not_called()


def test_tokens_are_resolved_once_for_the_whole_run():
    with mock.patch.object(core, "conf", _on()), \
         mock.patch.object(core, "resolve_project_uuids",
                           return_value={"tok-1": "uuid-1"}) as resolve:
        core.prepare_enrichment(["tok-1", "tok-2"])
    resolve.assert_called_once_with(["tok-1", "tok-2"])


def test_an_unresolved_token_is_skipped_without_a_fetch():
    core.project_uuid_map = {"tok-1": "uuid-1"}
    with mock.patch.object(core, "conf", _on()), \
         mock.patch.object(core, "fetch_project_enrichment") as fetch:
        assert core.enrich_project("tok-2") == {}
    fetch.assert_not_called()


def test_a_resolved_token_is_fetched_by_uuid():
    core.project_uuid_map = {"tok-1": "uuid-1"}
    with mock.patch.object(core, "conf", _on()), \
         mock.patch.object(core, "fetch_project_enrichment",
                           return_value={("CVE-1", "lib-1"): {}}) as fetch:
        assert core.enrich_project("tok-1") == {("CVE-1", "lib-1"): {}}
    fetch.assert_called_once_with("uuid-1")


def test_resolution_failure_disables_enrichment_for_the_rest_of_the_run():
    # Without this, a non-entitled org repeats login + retry for every one of ~400 projects.
    with mock.patch.object(core, "conf", _on()), \
         mock.patch.object(core, "resolve_project_uuids", return_value={}) as resolve:
        core.prepare_enrichment(["tok-1"])
        assert core.enrichment_disabled is True
        assert core.enrich_project("tok-1") == {}
        core.prepare_enrichment(["tok-1"])
    assert resolve.call_count == 1


def test_enrichment_never_raises_out_of_enrich_project():
    core.project_uuid_map = {"tok-1": "uuid-1"}
    with mock.patch.object(core, "conf", _on()), \
         mock.patch.object(core, "fetch_project_enrichment", side_effect=TypeError("boom")):
        assert core.enrich_project("tok-1") == {}
