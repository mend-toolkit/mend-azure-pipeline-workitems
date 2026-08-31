from mend_azure_wi_sync import core


def test_set_lastrun_no_longer_exists():
    """The write was the hard blocker: a 403 on it exited the run at startup."""
    assert not hasattr(core, "set_lastrun")


def test_the_legacy_property_migration_read_is_gone():
    """migration_seed was the last reader of the Azure Lastrun project property."""
    assert not hasattr(core, "migration_seed")
