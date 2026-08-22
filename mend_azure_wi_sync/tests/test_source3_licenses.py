from mend_azure_wi_sync import source3


def _row(lib="log4j-core", name="MIT", url="https://opensource.org/licenses/MIT",
         reference="https://repo.maven.apache.org/log4j-core.pom"):
    return {"name": name, "component": {"name": lib},
            "license": {"textUrl": url, "liabilityReference": reference}}


def test_index_is_keyed_by_library_name_and_carries_name_url_reference_file():
    index = source3.normalise_licenses([_row()])
    assert index == {"log4j-core": [
        {"name": "MIT", "url": "https://opensource.org/licenses/MIT",
         "reference_file": "https://repo.maven.apache.org/log4j-core.pom"}]}


def test_multiple_licenses_for_one_library_accumulate_into_a_list():
    rows = [_row(name="MIT"), _row(name="Apache-2.0")]
    index = source3.normalise_licenses(rows)
    assert [entry["name"] for entry in index["log4j-core"]] == ["MIT", "Apache-2.0"]


def test_two_libraries_stay_separate():
    rows = [_row(lib="log4j-core"), _row(lib="guava")]
    index = source3.normalise_licenses(rows)
    assert set(index) == {"log4j-core", "guava"}


def test_a_row_with_no_library_name_is_skipped():
    rows = [{"name": "MIT", "component": {}, "license": {}}, _row()]
    index = source3.normalise_licenses(rows)
    assert list(index) == ["log4j-core"]


def test_a_row_missing_the_license_object_still_gets_an_entry_with_empty_fields():
    """A malformed license sub-object must not drop the row -- only a missing library name
    does that."""
    rows = [{"name": "MIT", "component": {"name": "log4j-core"}}]
    index = source3.normalise_licenses(rows)
    assert index == {"log4j-core": [{"name": "MIT", "url": "", "reference_file": ""}]}


def test_a_non_dict_row_is_skipped_not_fatal():
    index = source3.normalise_licenses([_row(), "nope", 42, None])
    assert list(index) == ["log4j-core"]


def test_normalise_licenses_of_none_returns_empty_dict():
    assert source3.normalise_licenses(None) == {}


def test_normalise_licenses_of_garbage_list_returns_empty_dict():
    assert source3.normalise_licenses(["nope"]) == {}


def test_normalise_licenses_of_empty_list_returns_empty_dict():
    assert source3.normalise_licenses([]) == {}
