import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs
from mend_azure_wi_sync.tests.test_routing_config import _valid_conf


def test_mend_epss_and_mend_alert_are_gone():
    """EPSS and Exploit Code Maturity render unconditionally now -- both arrive inline with the
    3.0 finding, so there is nothing to spare an org by hiding them. MEND_ALERT gated the 1.4
    ignored-alerts filter; 3.0's findingInfo.status handles suppression natively."""
    from mend_azure_wi_sync.config import Config
    for gone in ("epss", "wsalert"):
        assert gone not in Config.__dataclass_fields__
    for gone in ("wsepss", "wsalert"):
        assert not hasattr(varenvs, gone)
    assert not hasattr(core, "epss_enabled")


def test_reachability_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_REACHABILITY": "true"}, clear=True):
        assert varenvs.get_env("wsreachability") == "true"
    with mock.patch.dict(os.environ, {"WS_REACHABILITY": "true"}, clear=True):
        assert varenvs.get_env("wsreachability") == "true"


def test_unexpanded_placeholder_and_empty_both_default_reachability_to_false():
    for raw in ("$(MEND_REACHABILITY)", ""):
        conf = _valid_conf(reachability=raw)
        conf.update_properties()
        assert conf.reachability == "false"


def test_check_patterns_rejects_a_mistyped_reachability_value():
    with mock.patch.object(core, "conf", _valid_conf(reachability="yes")):
        assert any("MEND_REACHABILITY" in el for el in core.check_patterns())


def test_check_patterns_accepts_valid_reachability_values():
    for value in ("true", "false", "TRUE", "False"):
        with mock.patch.object(core, "conf", _valid_conf(reachability=value)):
            assert not any("MEND_REACHABILITY" in el for el in core.check_patterns())


def test_enrichment_no_longer_requires_mend_email():
    """MEND_EMAIL existed for the 2.0/3.0 login. Config no longer carries an `email` field at
    all, so this asserts on the surviving validation list rather than on a false value."""
    with mock.patch.object(core, "conf", _valid_conf(reachability="true")):
        assert not [el for el in core.check_patterns() if "MEND_EMAIL" in el]
