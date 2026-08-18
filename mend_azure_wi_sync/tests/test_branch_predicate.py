from mend_azure_wi_sync.routing import branch_allowed


def test_main_and_master_match_the_defaults():
    assert branch_allowed("refs/heads/main", "main,master") is True
    assert branch_allowed("refs/heads/master", "main,master") is True


def test_feature_branch_is_excluded_by_default():
    assert branch_allowed("refs/heads/feature/tools", "main,master") is False


def test_glob_pattern_matches_a_nested_branch():
    assert branch_allowed("refs/heads/release/1.2", "main,release/*") is True


def test_glob_does_not_match_an_unrelated_branch():
    assert branch_allowed("refs/heads/hotfix/1.2", "main,release/*") is False


def test_bare_branch_name_without_a_ref_prefix_is_accepted():
    """Tolerate a scan template that tagged Build.SourceBranchName by mistake."""
    assert branch_allowed("main", "main,master") is True


def test_whitespace_in_the_pattern_list_is_ignored():
    assert branch_allowed("refs/heads/main", " main , master ") is True


def test_empty_branch_is_not_allowed():
    assert branch_allowed("", "main,master") is False


def test_empty_pattern_list_allows_nothing():
    """Failing closed is correct: an empty policy must not silently sync every branch."""
    assert branch_allowed("refs/heads/main", "") is False
