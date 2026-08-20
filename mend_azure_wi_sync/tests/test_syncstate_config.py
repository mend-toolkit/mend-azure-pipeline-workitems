import os
from unittest import mock

from mend_azure_wi_sync import core
from mend_azure_wi_sync.config import varenvs
from mend_azure_wi_sync.tests.test_routing_config import _valid_conf


def test_maxlookback_reads_both_aliases():
    with mock.patch.dict(os.environ, {"MEND_MAXLOOKBACK": "48"}, clear=True):
        assert varenvs.get_env("wsmaxlookback") == "48"
    with mock.patch.dict(os.environ, {"WS_MAXLOOKBACK": "48"}, clear=True):
        assert varenvs.get_env("wsmaxlookback") == "48"


def test_unexpanded_placeholder_and_empty_both_default_to_720():
    for raw in ("$(MEND_MAXLOOKBACK)", ""):
        conf = _valid_conf(maxlookback=raw)
        conf.update_properties()
        assert conf.maxlookback == "720"


def test_check_patterns_rejects_a_non_numeric_maxlookback():
    with mock.patch.object(core, "conf", _valid_conf(maxlookback="thirty")):
        assert any("MAXLOOKBACK" in el for el in core.check_patterns())


def test_check_patterns_rejects_a_non_positive_maxlookback():
    for raw in ("0", "-5"):
        with mock.patch.object(core, "conf", _valid_conf(maxlookback=raw)):
            assert any("MAXLOOKBACK" in el for el in core.check_patterns())


def test_check_patterns_accepts_a_positive_maxlookback():
    with mock.patch.object(core, "conf", _valid_conf(maxlookback="720")):
        assert not any("MAXLOOKBACK" in el for el in core.check_patterns())
