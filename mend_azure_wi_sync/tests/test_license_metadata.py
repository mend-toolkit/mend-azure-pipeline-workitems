"""License work items carry the library metadata the due-diligence rows already contain.

A license entry's findings are ProjectViolationDTOV3 objects, and that DTO has NO component --
no version, no paths, no home page. The data does exist, in the SAME due-diligence response
that already supplies the license names (DueDiligenceDTOV3.component, a LibraryComponentDTOV3),
so nothing here costs an extra API call. Before this, render_inputs returned blanks for a
license entry and the rendered work item showed empty "Path to dependency file", "Path to
library", and "Library home page" lines.

The second rule tested here: a line whose value is empty is NOT rendered at all. Mend can match
a library by filename alone, in which case it genuinely has no path to report, and a bold label
followed by nothing reads as a bug to an operator.
"""

from unittest import mock

from mend_azure_wi_sync import core, source3


def _dd_row(lib="log4j-core", name="GPL-3.0"):
    """One DueDiligenceDTOV3 row: a library/license pairing."""
    return {
        "name": name,
        "component": {
            "name": lib,
            "uuid": "lib-uuid-log4j-core",
            "version": "2.14.1",
            "description": "Apache Log4j Core",
            "dependencyType": "Transitive",
            "dependencyFile": "/src/pom.xml",
            "localPath": "/root/.m2/log4j-core-2.14.1.jar",
            "references": {"homePage": "https://logging.apache.org/log4j/"},
        },
        "license": {"textUrl": "https://opensource.org/licenses/GPL-3.0",
                    "liabilityReference": "/src/pom.xml"},
    }


def _conf(**overrides):
    values = dict(azure_type="Task", dependency="true", reachability="false",
                  reponame="", routing="false", description="Description", priority="false",
                  azure_area="", azure_project="TestProj", ws_user_key="uk-1")
    values.update(overrides)
    return mock.MagicMock(**values)


# ---------------------------------------------------------------- normalise_library_components

def test_component_index_is_keyed_by_library_and_carries_the_render_fields():
    index = source3.normalise_library_components([_dd_row()])
    assert index == {"log4j-core": {
        "version": "2.14.1",
        "description": "Apache Log4j Core",
        "dependency_type": "Transitive",
        "dependency_file": "/src/pom.xml",
        "library_path": "/root/.m2/log4j-core-2.14.1.jar",
        "home_page": "https://logging.apache.org/log4j/",
        "mend_url": "https://logging.apache.org/log4j/",
        "library_uuid": "lib-uuid-log4j-core",
    }}


def test_path_falls_back_to_component_path_when_local_path_is_absent():
    row = _dd_row()
    row["component"].pop("localPath")
    row["component"]["path"] = "/opt/lib/log4j-core.jar"
    index = source3.normalise_library_components([row])
    assert index["log4j-core"]["library_path"] == "/opt/lib/log4j-core.jar"


def test_home_page_falls_back_to_extra_data_homepage():
    """DueDiligenceDTOV3 carries extraData.homepage as well as component.references.homePage;
    either is a real answer, so neither alone may be required."""
    row = _dd_row()
    row["component"].pop("references")
    row["extraData"] = {"homepage": "https://fallback.example/"}
    index = source3.normalise_library_components([row])
    assert index["log4j-core"]["home_page"] == "https://fallback.example/"


def test_a_later_row_fills_a_field_an_earlier_row_left_blank():
    """A library appears once per license it carries, so the same component arrives several
    times. First non-empty wins per field rather than last row wins, so one sparse row cannot
    blank out data another row supplied."""
    sparse = _dd_row(name="MIT")
    sparse["component"]["dependencyFile"] = ""
    sparse["component"]["localPath"] = ""
    full = _dd_row(name="GPL-3.0")
    index = source3.normalise_library_components([sparse, full])
    assert index["log4j-core"]["dependency_file"] == "/src/pom.xml"
    assert index["log4j-core"]["library_path"] == "/root/.m2/log4j-core-2.14.1.jar"


def test_rows_with_no_library_name_or_no_component_are_skipped():
    rows = [{"name": "MIT"}, {"name": "MIT", "component": {}}, _dd_row()]
    assert list(source3.normalise_library_components(rows)) == ["log4j-core"]


def test_garbage_input_returns_an_empty_index_rather_than_raising():
    assert source3.normalise_library_components(None) == {}
    assert source3.normalise_library_components(["nope", 42, None]) == {}
    assert source3.normalise_library_components([]) == {}


def test_library_uuid_is_carried_and_first_non_empty_wins():
    sparse = _dd_row(name="MIT")
    sparse["component"]["uuid"] = ""
    full = _dd_row(name="GPL-3.0")
    index = source3.normalise_library_components([sparse, full])
    assert index["log4j-core"]["library_uuid"] == "lib-uuid-log4j-core"


def test_library_uuid_is_always_present_and_a_string_when_unknown():
    row = _dd_row()
    row["component"].pop("uuid")
    index = source3.normalise_library_components([row])
    assert index["log4j-core"]["library_uuid"] == ""


# ------------------------------------------------------------------------------- render_inputs

def _license_entry(component=None):
    entry = {
        "library": "log4j-core",
        "kind": "license",
        "findings": [{"findingType": "LEGAL", "originName": "log4j-core",
                      "name": "[Legal] No GPL"}],
        "licenses": [{"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
                      "reference_file": "/src/pom.xml"}],
    }
    if component is not None:
        entry["component"] = component
    return entry


def test_license_entry_renders_the_attached_component_metadata():
    entry = _license_entry(source3.normalise_library_components([_dd_row()])["log4j-core"])
    result = source3.render_inputs(entry)
    assert result["library"] == "log4j-core"
    assert result["version"] == "2.14.1"
    assert result["description"] == "Apache Log4j Core"
    assert result["dependency_type"] == "Transitive"
    assert result["dependency_file"] == "/src/pom.xml"
    assert result["library_path"] == "/root/.m2/log4j-core-2.14.1.jar"
    assert result["home_page"] == "https://logging.apache.org/log4j/"
    # A license entry has no findings to render CVEs or a dependency hierarchy from.
    assert result["vulnerabilities"] == []
    assert result["parents"] == []


def test_license_entry_with_no_component_attached_still_yields_blanks_not_an_error():
    result = source3.render_inputs(_license_entry())
    assert result["dependency_file"] == ""
    assert result["library_path"] == ""
    assert result["home_page"] == ""


def test_a_malformed_component_is_ignored_rather_than_fatal():
    entry = _license_entry("not-a-dict")
    assert source3.render_inputs(entry)["library_path"] == ""


def test_a_vulnerability_entry_still_reads_its_finding_not_the_attached_component():
    """The component index exists for license entries. A vulnerability finding carries its own
    component (with libraryLocations), and that must stay authoritative."""
    entry = {
        "library": "log4j-core",
        "kind": "vulnerability",
        "findings": [{"component": {"name": "log4j-core", "version": "2.17.0",
                                    "localPath": "/from/finding.jar"},
                      "vulnerability": {"name": "CVE-2021-44228", "score": 10.0}}],
        "component": {"version": "2.14.1", "library_path": "/from/index.jar"},
    }
    result = source3.render_inputs(entry)
    assert result["version"] == "2.17.0"
    assert result["library_path"] == "/from/finding.jar"


# ------------------------------------------------------------------- omit-when-empty rendering

def test_library_block_omits_the_path_lines_when_both_paths_are_empty():
    inputs = source3.render_inputs(_license_entry())
    block = core.library_block_v3(inputs, with_hierarchy=False)
    assert "Path to dependency file" not in block
    assert "Path to library" not in block
    assert "Library home page" not in block


def test_library_block_renders_only_the_path_line_it_has_a_value_for():
    inputs = source3.render_inputs(_license_entry({"dependency_file": "/src/pom.xml"}))
    block = core.library_block_v3(inputs, with_hierarchy=False)
    assert "Path to dependency file: </b>/src/pom.xml" in block
    assert "Path to library" not in block


def test_library_block_renders_every_line_when_every_value_is_present():
    inputs = source3.render_inputs(
        _license_entry(source3.normalise_library_components([_dd_row()])["log4j-core"]))
    block = core.library_block_v3(inputs, with_hierarchy=False)
    assert "Path to dependency file: </b>/src/pom.xml" in block
    assert "Path to library:</b>/root/.m2/log4j-core-2.14.1.jar" in block
    assert "https://logging.apache.org/log4j/" in block


def test_license_details_omits_the_reference_file_line_when_mend_reports_none():
    """license.liabilityReference is the ONLY source 3.0 offers for this line -- there is no
    second field to fall back to -- so when it is empty the label must not be rendered."""
    html = core.build_license_html_v3(
        [{"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
          "reference_file": ""}], "No GPL")
    assert "License Reference File" not in html
    assert "GPL-3.0" in html
    assert "License Policy Violation - </b>No GPL" in html


def test_license_details_renders_the_reference_file_line_when_present():
    html = core.build_license_html_v3(
        [{"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
          "reference_file": "/src/pom.xml"}], "No GPL")
    assert "License Reference File: </b><a href='/src/pom.xml'>/src/pom.xml</a>" in html


def test_a_license_with_no_text_url_renders_its_name_as_plain_text():
    html = core.build_license_html_v3([{"name": "GPL-3.0", "url": "", "reference_file": ""}], "x")
    assert "GPL-3.0" in html
    assert "href=''" not in html


# ------------------------------------------------------------------------------ the fetch join

def _fake_pages(license_rows):
    def pages(path, **kwargs):
        if path.endswith("libraries/licenses"):
            return license_rows, True
        if path.endswith("/violations"):
            return [{"findingType": "LEGAL", "originName": "log4j-core",
                     "name": "[Legal] No GPL"}], True
        return [], True
    return pages


def test_fetch_v3_desired_attaches_the_component_index_to_license_entries():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages([_dd_row()])):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    entry = desired[("license", "log4j-core")]
    assert entry["component"]["library_path"] == "/root/.m2/log4j-core-2.14.1.jar"
    assert entry["component"]["dependency_file"] == "/src/pom.xml"


def test_a_license_violation_with_no_due_diligence_row_gets_an_empty_component():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages([])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    assert desired[("license", "log4j-core")]["component"] == {}


def test_the_rendered_license_work_item_shows_the_paths_end_to_end():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages([_dd_row()])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    entry = desired[("license", "log4j-core")]
    items = core.render_entry_v3("license", "log4j-core", entry, reachability_on=False)
    desc = items[0]["desc"]
    assert "Path to dependency file: </b>/src/pom.xml" in desc
    assert "Path to library:</b>/root/.m2/log4j-core-2.14.1.jar" in desc
    assert "https://logging.apache.org/log4j/" in desc
    assert "License Reference File: </b><a href='/src/pom.xml'>/src/pom.xml</a>" in desc


# ============================================================ the 1.4-equivalent library source
#
# 1.4 populated these lines from a DEDICATED per-project call, getProjectLibraryLocations, keyed
# by library keyUuid (core.py get_pathes, deleted in 9957482):
#
#     return try_or_error(lambda: location_['locations'][0]['dependencyFile'], ""), \
#            try_or_error(lambda: location_['locations'][0]['path'], "")
#
# and the license reference file from getProjectLicenses -> licenses[].references[0].reference,
# an ARRAY. The 3.0 equivalent of both is GET /projects/{uuid}/dependencies/libraries ->
# LibraryDTOV3, which carries locations[] and licenses[].licenseReferences[] in the same shapes.
# Due diligence stays as the fallback: its projection is a single scalar per field, so it can
# fill a gap but must not be the primary.


def _lib_row(lib="log4j-core", locations=None, licenses=None):
    """One LibraryDTOV3 row."""
    return {
        "name": lib,
        "uuid": "lib-uuid-log4j-core",
        "version": "2.14.1",
        "description": "Apache Log4j Core (libraries call)",
        "dependencyType": "Transitive",
        "locations": locations if locations is not None else [
            {"localPath": "/root/.m2/log4j-core-2.14.1.jar", "dependencyFile": "/src/pom.xml"}],
        "extraInformation": {"homePage": "https://logging.apache.org/log4j/"},
        "licenses": licenses if licenses is not None else [
            {"name": "GPL-3.0", "licenseReferences": [
                {"liabilityReference": "/src/pom.xml",
                 "textUrl": "https://opensource.org/licenses/GPL-3.0"}]}],
    }


def test_library_rows_yield_the_same_component_shape_as_due_diligence():
    index = source3.normalise_libraries([_lib_row()])
    assert index == {"log4j-core": {
        "version": "2.14.1",
        "description": "Apache Log4j Core (libraries call)",
        "dependency_type": "Transitive",
        "dependency_file": "/src/pom.xml",
        "library_path": "/root/.m2/log4j-core-2.14.1.jar",
        "home_page": "https://logging.apache.org/log4j/",
        # LibraryDTOV3 carries no ComponentReferencesDTO -- due diligence fills this on merge.
        "mend_url": "",
        "library_uuid": "lib-uuid-log4j-core",
    }}


def test_library_uuid_is_carried_from_the_libraries_call():
    row = _lib_row()
    row["uuid"] = ""
    index = source3.normalise_libraries([row])
    assert index["log4j-core"]["library_uuid"] == ""
    assert source3.normalise_libraries([_lib_row()])["log4j-core"]["library_uuid"] \
        == "lib-uuid-log4j-core"


def test_paths_come_from_the_first_location_that_has_them():
    """1.4 read locations[0] positionally. A leading location with neither field is a hole that
    positional access turns into a blank line, so the first location carrying each value wins."""
    row = _lib_row(locations=[{}, {"dependencyFile": "/a/pom.xml"},
                              {"localPath": "/b/lib.jar", "dependencyFile": "/b/pom.xml"}])
    index = source3.normalise_libraries([row])
    assert index["log4j-core"]["dependency_file"] == "/a/pom.xml"
    assert index["log4j-core"]["library_path"] == "/b/lib.jar"


def test_dependency_type_falls_back_to_the_direct_dependency_flag():
    row = _lib_row()
    row.pop("dependencyType")
    row["directDependency"] = True
    assert source3.normalise_libraries([row])["log4j-core"]["dependency_type"] == "Direct"
    row["directDependency"] = False
    assert source3.normalise_libraries([row])["log4j-core"]["dependency_type"] == "Transitive"


def test_a_library_row_with_no_locations_yields_blank_paths_not_an_error():
    index = source3.normalise_libraries([_lib_row(locations=[])])
    assert index["log4j-core"]["dependency_file"] == ""
    assert index["log4j-core"]["library_path"] == ""


def test_library_rows_with_no_name_or_garbage_are_skipped():
    assert source3.normalise_libraries([{"version": "1"}, "nope", None, _lib_row()]) \
        == {"log4j-core": source3.normalise_libraries([_lib_row()])["log4j-core"]}
    assert source3.normalise_libraries(None) == {}


def test_license_list_from_library_rows_reads_the_reference_array():
    """1.4's reference file was licenses[].references[0].reference -- a LIST. 3.0's
    licenseReferences[] is the same shape, and the first entry carrying a liabilityReference
    wins over an earlier one that has none."""
    row = _lib_row(licenses=[{"name": "GPL-3.0", "licenseReferences": [
        {"textUrl": "https://opensource.org/licenses/GPL-3.0"},
        {"liabilityReference": "/src/pom.xml"}]}])
    assert source3.normalise_library_licenses([row]) == {"log4j-core": [
        {"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
         "reference_file": "/src/pom.xml"}]}


def test_a_library_with_several_licenses_keeps_them_all_in_order():
    row = _lib_row(licenses=[{"name": "MIT"}, {"name": "Apache-2.0"}])
    assert [lic["name"] for lic in source3.normalise_library_licenses([row])["log4j-core"]] \
        == ["MIT", "Apache-2.0"]


def test_license_rows_with_no_name_are_skipped_and_garbage_never_raises():
    row = _lib_row(licenses=[{"licenseReferences": []}, "nope", {"name": "MIT"}])
    assert [lic["name"] for lic in source3.normalise_library_licenses([row])["log4j-core"]] == ["MIT"]
    assert source3.normalise_library_licenses(None) == {}


# ------------------------------------------------------------------------------- the union rule

def test_merge_prefers_the_primary_and_fills_only_its_blanks():
    primary = {"log4j-core": {"version": "2.14.1", "description": "", "dependency_type": "",
                              "dependency_file": "/src/pom.xml", "library_path": "",
                              "home_page": ""}}
    fallback = {"log4j-core": {"version": "9.9.9", "description": "from dd",
                               "dependency_type": "Direct", "dependency_file": "/dd/pom.xml",
                               "library_path": "/dd/lib.jar", "home_page": "https://dd/"},
                "guava": {"version": "31.0", "description": "", "dependency_type": "",
                          "dependency_file": "", "library_path": "", "home_page": ""}}
    merged = source3.merge_component_index(primary, fallback)
    # primary wins where it has a value
    assert merged["log4j-core"]["version"] == "2.14.1"
    assert merged["log4j-core"]["dependency_file"] == "/src/pom.xml"
    # fallback fills every blank
    assert merged["log4j-core"]["library_path"] == "/dd/lib.jar"
    assert merged["log4j-core"]["home_page"] == "https://dd/"
    assert merged["log4j-core"]["description"] == "from dd"
    # a library only the fallback knows about is kept, not dropped
    assert merged["guava"]["version"] == "31.0"


def test_merging_licenses_unions_by_license_name_and_fills_blank_fields():
    primary = {"log4j-core": [{"name": "GPL-3.0", "url": "", "reference_file": "/src/pom.xml"}]}
    fallback = {"log4j-core": [
        {"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
         "reference_file": "/dd/pom.xml"},
        {"name": "MIT", "url": "https://opensource.org/licenses/MIT", "reference_file": ""}]}
    merged = source3.merge_license_index(primary, fallback)
    gpl, mit = merged["log4j-core"]
    assert gpl["reference_file"] == "/src/pom.xml"                      # primary wins
    assert gpl["url"] == "https://opensource.org/licenses/GPL-3.0"      # blank filled
    assert mit["name"] == "MIT"                                         # fallback-only kept


def test_merging_an_empty_primary_returns_the_fallback_unchanged():
    fallback = {"log4j-core": [{"name": "MIT", "url": "u", "reference_file": "r"}]}
    assert source3.merge_license_index({}, fallback) == fallback
    assert source3.merge_component_index({}, {"a": {"version": "1"}}) == {"a": {"version": "1"}}


# --------------------------------------------------------------------- the fetch join, extended

def _fake_pages_v2(lib_rows, dd_rows, lib_ok=True):
    def pages(path, **kwargs):
        if path.endswith("libraries/licenses"):
            return dd_rows, True
        if path.endswith("dependencies/libraries"):
            return lib_rows, lib_ok
        if path.endswith("/violations"):
            return [{"findingType": "LEGAL", "originName": "log4j-core",
                     "name": "[Legal] No GPL"}], True
        return [], True
    return pages


def test_the_libraries_call_is_the_primary_source_for_a_license_work_item():
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_v2([_lib_row()], [_dd_row()])):
        desired, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is True
    entry = desired[("license", "log4j-core")]
    assert entry["component"]["description"] == "Apache Log4j Core (libraries call)"
    assert entry["component"]["library_path"] == "/root/.m2/log4j-core-2.14.1.jar"


def test_due_diligence_fills_a_field_the_libraries_call_left_blank():
    sparse = _lib_row(locations=[])
    sparse["extraInformation"] = {}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_v2([sparse], [_dd_row()])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    component = desired[("license", "log4j-core")]["component"]
    assert component["dependency_file"] == "/src/pom.xml"                  # from due diligence
    assert component["library_path"] == "/root/.m2/log4j-core-2.14.1.jar"   # from due diligence
    assert component["home_page"] == "https://logging.apache.org/log4j/"    # from due diligence


def test_a_failed_libraries_read_clears_ok_so_nothing_is_closed():
    """Same interlock as every other read in fetch_v3_desired: a partial read must not be
    mistaken for a shrunken desired, or reconciliation closes live work items."""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages",
                           _fake_pages_v2([], [_dd_row()], lib_ok=False)):
        _, ok = core.fetch_v3_desired("p-1", 7.0)
    assert ok is False


def test_a_vulnerability_finding_missing_its_paths_falls_back_to_the_library_index():
    """1.4 rendered these lines from the location index for EVERY work item, license or CVE --
    the index was keyed by library and never consulted the violation. A finding whose component
    carries no path must therefore still show one if the project's library list has it."""
    entry = {
        "library": "log4j-core",
        "kind": "vulnerability",
        "findings": [{"component": {"name": "log4j-core", "version": "2.14.1"},
                      "vulnerability": {"name": "CVE-2021-44228", "score": 10.0}}],
        "component": {"dependency_file": "/src/pom.xml", "library_path": "/m2/log4j.jar",
                      "home_page": "https://logging.apache.org/log4j/"},
    }
    result = source3.render_inputs(entry)
    assert result["dependency_file"] == "/src/pom.xml"
    assert result["library_path"] == "/m2/log4j.jar"
    assert result["home_page"] == "https://logging.apache.org/log4j/"


def test_the_finding_still_wins_over_the_index_when_it_has_its_own_paths():
    entry = {
        "library": "log4j-core",
        "kind": "vulnerability",
        "findings": [{"component": {"name": "log4j-core", "localPath": "/from/finding.jar",
                                    "dependencyFile": "/from/finding-pom.xml"},
                      "vulnerability": {"name": "CVE-2021-44228", "score": 10.0}}],
        "component": {"dependency_file": "/from/index-pom.xml", "library_path": "/from/index.jar"},
    }
    result = source3.render_inputs(entry)
    assert result["library_path"] == "/from/finding.jar"
    assert result["dependency_file"] == "/from/finding-pom.xml"


# ==================================================== the License Details link, and the missing
#                                                      Hyperlink relation on a license work item
#
# 1.4 rendered the license NAME as a link: f"<a href='{lic_data_[2]}'>{lic_data_[1]}</a>", where
# [2] was getProjectLicenses -> libraries[].licenses[].url, an opensource.org-style license page.
#
# 3.0 exposes that value only as LicenseDTO.profile.links[] (example in the spec:
# "http://www.opensource.org/licenses/AFL-3.0"), and LicenseDTO is referenced ONLY by
# SourceFileLibraryDTO, which no path in references/3.0 (2).json returns. It is unreachable. The
# one license URL that IS reachable is LicenseReferenceDTO.textUrl, read from both sources.
#
# So the section falls back to the library's own Mend page rather than rendering dead text -- and
# that same URL fixes a second 1.4 regression: library_url() returns "" for a license entry, so
# license work items were being created with NO Hyperlink relation at all, where 1.4 had
# prj_el["library"]["url"] available for a license violation just as for a CVE.


def test_the_component_index_carries_the_libraries_mend_page():
    """ComponentReferencesDTO.url is the library's page in Mend; homePage is the upstream
    project's own site, so it is only a fallback -- same precedence library_url already uses."""
    row = _dd_row()
    row["component"]["references"] = {"url": "https://mend.example/library/log4j-core",
                                      "homePage": "https://logging.apache.org/log4j/"}
    index = source3.normalise_library_components([row])
    assert index["log4j-core"]["mend_url"] == "https://mend.example/library/log4j-core"
    assert index["log4j-core"]["home_page"] == "https://logging.apache.org/log4j/"


def test_mend_page_falls_back_to_the_home_page_when_there_is_no_library_page():
    index = source3.normalise_library_components([_dd_row()])
    assert index["log4j-core"]["mend_url"] == "https://logging.apache.org/log4j/"


def test_library_url_falls_back_to_the_component_index_for_a_license_entry():
    """A license entry's violations carry no component, so without the index there is no URL to
    write and the work item gets no Hyperlink relation -- a 1.4 regression."""
    entry = _license_entry({"mend_url": "https://mend.example/library/log4j-core"})
    assert source3.library_url(entry) == "https://mend.example/library/log4j-core"


def test_library_url_still_prefers_the_findings_own_component():
    entry = {
        "kind": "vulnerability",
        "findings": [{"component": {"references": {"url": "https://mend.example/from-finding"}}}],
        "component": {"mend_url": "https://mend.example/from-index"},
    }
    assert source3.library_url(entry) == "https://mend.example/from-finding"


def test_library_url_is_empty_when_neither_source_has_one():
    assert source3.library_url(_license_entry()) == ""
    assert source3.library_url(_license_entry({"mend_url": ""})) == ""


def test_license_name_links_to_the_license_text_url_when_mend_has_one():
    html = core.build_license_html_v3(
        [{"name": "GPL-3.0", "url": "https://opensource.org/licenses/GPL-3.0",
          "reference_file": ""}], "No GPL", library_url="https://mend.example/library/log4j-core")
    assert "<a href='https://opensource.org/licenses/GPL-3.0'>GPL-3.0</a>" in html


def test_license_name_falls_back_to_the_library_page_when_there_is_no_license_url():
    """A section whose only content is dead text tells an operator nothing. The library's Mend
    page is a real link to where Mend shows this license and its evidence."""
    html = core.build_license_html_v3(
        [{"name": "GPL-3.0", "url": "", "reference_file": ""}], "No GPL",
        library_url="https://mend.example/library/log4j-core")
    assert "<a href='https://mend.example/library/log4j-core'>GPL-3.0</a>" in html


def test_license_name_is_plain_text_only_when_no_url_exists_at_all():
    html = core.build_license_html_v3([{"name": "GPL-3.0", "url": "", "reference_file": ""}],
                                      "No GPL", library_url="")
    assert "GPL-3.0" in html
    assert "href" not in html


def test_a_license_work_item_is_rendered_with_its_library_page_link_end_to_end():
    row = _dd_row()
    row["component"]["references"] = {"url": "https://mend.example/library/log4j-core"}
    row["license"]["textUrl"] = ""
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_v2([], [row])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    entry = desired[("license", "log4j-core")]
    desc = core.render_entry_v3("license", "log4j-core", entry, reachability_on=False)[0]["desc"]
    assert "<a href='https://mend.example/library/log4j-core'>GPL-3.0</a>" in desc
    # and the same URL is what the work item's Hyperlink relation carries
    assert source3.library_url(entry) == "https://mend.example/library/log4j-core"


# ================================================ LibraryExtraInfoDTO.licenseUrl, the closest
#                                                  reachable analogue of 1.4's licenses[].url
#
# extraInformation.licenseUrl rides on the libraries call already being made. It is per-LIBRARY,
# not per-license, so it is only attributed to a license when the library carries exactly one --
# handing the same URL to two different licenses states something Mend did not.


def test_license_url_comes_from_extra_information_when_there_is_no_text_url():
    row = _lib_row(licenses=[{"name": "MIT"}])
    row["extraInformation"] = {"homePage": "https://x/", "licenseUrl": "https://opensource.org/MIT"}
    assert source3.normalise_library_licenses([row]) == {"log4j-core": [
        {"name": "MIT", "url": "https://opensource.org/MIT", "reference_file": ""}]}


def test_a_licenses_own_text_url_still_wins_over_the_library_wide_one():
    row = _lib_row(licenses=[{"name": "MIT", "licenseReferences": [
        {"textUrl": "https://spdx.org/licenses/MIT.html"}]}])
    row["extraInformation"] = {"licenseUrl": "https://opensource.org/MIT"}
    assert source3.normalise_library_licenses([row])["log4j-core"][0]["url"] \
        == "https://spdx.org/licenses/MIT.html"


def test_the_library_wide_license_url_is_not_attributed_when_there_are_several_licenses():
    """One URL cannot describe two licenses. Those fall through to the library page instead."""
    row = _lib_row(licenses=[{"name": "MIT"}, {"name": "Apache-2.0"}])
    row["extraInformation"] = {"licenseUrl": "https://opensource.org/MIT"}
    assert [lic["url"] for lic in source3.normalise_library_licenses([row])["log4j-core"]] \
        == ["", ""]


def test_an_mit_license_with_only_a_library_wide_url_renders_as_a_link_end_to_end():
    row = _lib_row(licenses=[{"name": "MIT"}])
    row["extraInformation"] = {"licenseUrl": "https://opensource.org/licenses/MIT"}
    with mock.patch.object(core, "conf", _conf()), \
         mock.patch.object(core, "org_uuid", return_value="org-1"), \
         mock.patch.object(core, "fetch_v3_pages", _fake_pages_v2([row], [])):
        desired, _ = core.fetch_v3_desired("p-1", 7.0)
    desc = core.render_entry_v3("license", "log4j-core",
                                desired[("license", "log4j-core")], False)[0]["desc"]
    assert "<a href='https://opensource.org/licenses/MIT'>MIT</a>" in desc


# ============================================== diagnostics: which link source Mend actually has
#
# Every candidate for the License Details link is optional in 3.0, and which ones an org
# populates cannot be read off the spec. Rather than guess again, a run reports per library which
# sources were present, so one DEBUG run answers it.


def test_link_report_names_the_source_each_license_would_use():
    licenses = {"log4j-core": [{"name": "MIT", "url": "https://opensource.org/MIT",
                                "reference_file": ""}],
                "guava": [{"name": "Apache-2.0", "url": "", "reference_file": ""}],
                "jackson": [{"name": "MIT", "url": "", "reference_file": ""}]}
    components = {"log4j-core": {"mend_url": "https://mend.example/log4j"},
                  "guava": {"mend_url": "https://mend.example/guava"},
                  "jackson": {"mend_url": ""}}
    report = source3.license_link_report(licenses, components)
    assert report["license_url"] == ["log4j-core/MIT"]
    assert report["library_page"] == ["guava/Apache-2.0"]
    assert report["no_link"] == ["jackson/MIT"]


def test_link_report_is_empty_for_no_licenses_and_never_raises():
    assert source3.license_link_report({}, {}) == {"license_url": [], "library_page": [],
                                                   "no_link": []}
    assert source3.license_link_report(None, None) == {"license_url": [], "library_page": [],
                                                       "no_link": []}
    assert source3.license_link_report({"a": "nope"}, {"a": "nope"}) \
        == {"license_url": [], "library_page": [], "no_link": []}
