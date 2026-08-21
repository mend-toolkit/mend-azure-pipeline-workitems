import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs
from mend_azure_wi_sync.tests.test_routing_config import _valid_conf


def test_epss_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_EPSS": "true"}, clear=True):
        assert varenvs.get_env("wsepss") == "true"
    with mock.patch.dict(os.environ, {"WS_EPSS": "true"}, clear=True):
        assert varenvs.get_env("wsepss") == "true"


def test_reachability_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_REACHABILITY": "true"}, clear=True):
        assert varenvs.get_env("wsreachability") == "true"
    with mock.patch.dict(os.environ, {"WS_REACHABILITY": "true"}, clear=True):
        assert varenvs.get_env("wsreachability") == "true"


def test_unexpanded_placeholder_and_empty_both_default_epss_to_false():
    for raw in ("$(MEND_EPSS)", ""):
        conf = _valid_conf(epss=raw)
        conf.update_properties()
        assert conf.epss == "false"


def test_unexpanded_placeholder_and_empty_both_default_reachability_to_false():
    for raw in ("$(MEND_REACHABILITY)", ""):
        conf = _valid_conf(reachability=raw)
        conf.update_properties()
        assert conf.reachability == "false"


def test_check_patterns_rejects_a_mistyped_epss_value():
    with mock.patch.object(core, "conf", _valid_conf(epss="yes")):
        assert any("MEND_EPSS" in el for el in core.check_patterns())


def test_check_patterns_rejects_a_mistyped_reachability_value():
    with mock.patch.object(core, "conf", _valid_conf(reachability="yes")):
        assert any("MEND_REACHABILITY" in el for el in core.check_patterns())


def test_check_patterns_accepts_valid_epss_and_reachability_values():
    for value in ("true", "false", "TRUE", "False"):
        with mock.patch.object(core, "conf", _valid_conf(epss=value, reachability=value)):
            patterns = core.check_patterns()
            assert not any("MEND_EPSS" in el for el in patterns)
            assert not any("MEND_REACHABILITY" in el for el in patterns)


def test_enrichment_no_longer_requires_mend_email():
    """MEND_EMAIL existed for the 2.0/3.0 login. Enrichment reads the 1.4 alerts API now,
    which authenticates with MEND_USERKEY alone, so requiring an email would block a valid
    config for a login the tool never performs. Config no longer carries an `email` field at
    all, so this asserts on the surviving validation list rather than on a false value."""
    with mock.patch.object(core, "conf", _valid_conf(epss="true", reachability="true")):
        assert not [el for el in core.check_patterns() if "MEND_EMAIL" in el]
