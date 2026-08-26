from unittest import mock

from mend_azure_wi_sync import core


def _conf(**kw):
    base = dict(email="", org_uuid="", proxy={})
    base.update(kw)
    return mock.MagicMock(**base)


def test_org_uuid_has_no_fallback():
    """MEND_APIKEY is gone, so there is nothing left to fall back to. check_patterns is what
    stops a run with no MEND_ORGUUID -- see test_check_patterns_requires_the_org_uuid."""
    with mock.patch.object(core, "conf", _conf(org_uuid="")):
        assert core.org_uuid() == ""


def test_org_uuid_reads_the_configured_value():
    with mock.patch.object(core, "conf", _conf(org_uuid="uuid-xyz")):
        assert core.org_uuid() == "uuid-xyz"


def test_org_uuid_is_stripped():
    with mock.patch.object(core, "conf", _conf(org_uuid="  uuid-xyz  ")):
        assert core.org_uuid() == "uuid-xyz"


def test_config_carries_the_two_new_fields():
    """startup() must populate them; a missing attribute is an AttributeError at runtime."""
    for field in ("email", "org_uuid"):
        assert field in core.Config.__dataclass_fields__, f"Config is missing {field}"


def test_env_aliases_exist_for_both():
    from mend_azure_wi_sync.config import varenvs
    assert varenvs.wsemail.value == ("MEND_EMAIL",)
    assert varenvs.wsorguuid.value == ("MEND_ORGUUID",)


def test_the_api_key_is_gone_from_config_entirely():
    """MEND_APIKEY was the org identifier and the login orgToken. Both now read
    MEND_ORGUUID, so neither the variable nor the Config field survives -- and
    $MEND_APIKEY no longer resolves in MEND_CUSTOMFIELDS."""
    from mend_azure_wi_sync.config import Config, varenvs
    assert not hasattr(varenvs, "wsapikey")
    assert "ws_org_token" not in Config.__dataclass_fields__
    for member in varenvs:
        assert not any(str(v).startswith("WS_") for v in member.value), member.name
