import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs
from mend_azure_wi_sync.tests.test_routing_config import _valid_conf


def test_enrichment_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_ENRICHMENT": "true"}, clear=True):
        assert varenvs.get_env("wsenrichment") == "true"
    with mock.patch.dict(os.environ, {"WS_ENRICHMENT": "true"}, clear=True):
        assert varenvs.get_env("wsenrichment") == "true"


def test_unexpanded_placeholder_and_empty_both_default_to_false():
    for raw in ("$(MEND_ENRICHMENT)", ""):
        conf = _valid_conf(enrichment=raw)
        conf.update_properties()
        assert conf.enrichment == "false"


def test_check_patterns_rejects_a_mistyped_enrichment_value():
    with mock.patch.object(core, "conf", _valid_conf(enrichment="yes")):
        assert any("MEND_ENRICHMENT" in el for el in core.check_patterns())


def test_enrichment_no_longer_requires_mend_email():
    """MEND_EMAIL existed for the 2.0/3.0 login. Enrichment reads the 1.4 alerts API now,
    which authenticates with MEND_USERKEY alone, so requiring an email would block a valid
    config for a login the tool never performs. Config no longer carries an `email` field at
    all, so this asserts on the surviving validation list rather than on a false value."""
    with mock.patch.object(core, "conf", _valid_conf(enrichment="true")):
        assert not [el for el in core.check_patterns() if "MEND_EMAIL" in el]
