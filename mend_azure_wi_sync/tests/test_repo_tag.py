from mend_azure_wi_sync.core import build_wi_tags, tag_set


def test_repo_tag_is_added_under_routing():
    tags = build_wi_tags("ProductX/api", "security vulnerability", routing="true",
                         reponame="api-client")
    assert tags == ["ProductX/api", "security vulnerability", "api-client"]


def test_no_repo_tag_when_routing_is_off():
    tags = build_wi_tags("ProductX/api", "security vulnerability", routing="false",
                         reponame="api-client")
    assert tags == ["ProductX/api", "security vulnerability"]


def test_no_repo_tag_when_the_repo_is_unknown():
    """A missing repo tag must produce no tag at all, never a placeholder."""
    tags = build_wi_tags("ProductX/api", "security vulnerability", routing="true",
                         reponame="")
    assert tags == ["ProductX/api", "security vulnerability"]


def test_repo_name_survives_the_write_read_round_trip():
    """Written comma-joined, read back '; '-delimited. Both must yield an exact tag."""
    written = ",".join(build_wi_tags("ProductX/api", "security vulnerability",
                                     routing="true", reponame="api-client"))
    assert "api-client" in tag_set(written)
    assert "api-client" in tag_set(written.replace(",", "; "))


def test_prefix_overlapping_repo_names_stay_distinct():
    assert "api" not in tag_set("ProductX/api-client; security vulnerability; api-client")
