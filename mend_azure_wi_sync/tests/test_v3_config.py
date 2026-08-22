from unittest import mock

from mend_azure_wi_sync import core


def _conf(**kw):
    base = dict(email="", org_uuid="", ws_org_token="tok-abc", proxy={})
    base.update(kw)
    return mock.MagicMock(**base)


def test_org_uuid_falls_back_to_the_api_key():
    """The 1.4 org token and the 3.0 org UUID are plausibly the same value, so an operator
    who never sets MEND_ORGUUID must still get a working 3.0 client."""
    with mock.patch.object(core, "conf", _conf(org_uuid="")):
        assert core.org_uuid() == "tok-abc"


def test_an_explicit_org_uuid_wins():
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
    assert varenvs.wsemail.value == ("WS_EMAIL", "MEND_EMAIL")
    assert varenvs.wsorguuid.value == ("WS_ORGUUID", "MEND_ORGUUID")
