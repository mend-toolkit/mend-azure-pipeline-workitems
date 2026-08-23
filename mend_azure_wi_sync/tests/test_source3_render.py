from mend_azure_wi_sync import source3


def _finding(**overrides):
    finding = {
        "component": {
            "name": "lodash",
            "description": "Lodash modular utilities.",
            "version": "4.17.15",
            "dependencyType": "",
            "dependencyFile": "package.json",
            "localPath": "/app/node_modules/lodash",
            "path": "",
            "libraryLocations": [],
            "references": {
                "homePage": "https://lodash.com/",
                "url": "https://example.com/lodash",
            },
        },
        "dependencyContexts": [
            {
                "dependencyType": "DIRECT",
                "isDirect": True,
                "isTransitive": False,
                "directRoots": [
                    {"rootLibraryUuid": "u1", "rootLibraryName": "app", "rootLibraryVersion": "1.0.0"},
                ],
            }
        ],
        "vulnerability": {
            "name": "CVE-2020-8203",
            "description": "Prototype pollution.",
            "score": 7.4,
            "severity": "high",
            "publishDate": "2020-07-15",
            "references": [{"url": "https://nvd.nist.gov/vuln/CVE-2020-8203"}],
        },
        "topFix": {
            "type": "upgrade",
            "url": "https://example.com/fix",
            "fixResolution": "Upgrade to 4.17.19",
            "date": "2020-08-01",
        },
        "threatAssessment": {"epssPercentage": 0.5, "exploitCodeMaturity": "POC"},
        "reachability": "REACHABLE",
        "findingInfo": {"status": "ACTIVE"},
    }
    finding.update(overrides)
    return finding


def test_fields_are_lifted_from_component_and_references():
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [_finding()]}
    result = source3.render_inputs(entry)
    assert result["library"] == "lodash"
    assert result["version"] == "4.17.15"
    assert result["description"] == "Lodash modular utilities."
    assert result["home_page"] == "https://lodash.com/"
    assert result["dependency_file"] == "package.json"
    assert result["library_path"] == "/app/node_modules/lodash"


def test_dependency_type_prefers_component_then_falls_back_to_context():
    with_explicit = _finding(component={**_finding()["component"], "dependencyType": "Direct"})
    result = source3.render_inputs({"library": "lodash", "kind": "vulnerability", "findings": [with_explicit]})
    assert result["dependency_type"] == "Direct"

    finding = _finding()
    finding["component"] = {**finding["component"], "dependencyType": ""}
    result = source3.render_inputs({"library": "lodash", "kind": "vulnerability", "findings": [finding]})
    assert result["dependency_type"] == "Direct"  # isDirect True on the context

    finding2 = _finding()
    finding2["component"] = {**finding2["component"], "dependencyType": ""}
    finding2["dependencyContexts"] = [{"isDirect": False, "directRoots": []}]
    result2 = source3.render_inputs({"library": "lodash", "kind": "vulnerability", "findings": [finding2]})
    assert result2["dependency_type"] == "Transitive"


def test_dependency_file_and_path_fall_back_to_library_locations():
    finding = _finding()
    finding["component"] = {
        **finding["component"],
        "dependencyFile": "",
        "localPath": "",
        "path": "",
        "libraryLocations": [{"localPath": "/other/path", "dependencyFile": "pom.xml"}],
    }
    result = source3.render_inputs({"library": "lodash", "kind": "vulnerability", "findings": [finding]})
    assert result["dependency_file"] == "pom.xml"
    assert result["library_path"] == "/other/path"


def test_parents_are_deduped_and_order_stable():
    f1 = _finding()
    f2 = _finding()
    f2["dependencyContexts"] = [
        {"directRoots": [
            {"rootLibraryName": "app", "rootLibraryVersion": "1.0.0"},
            {"rootLibraryName": "other-app", "rootLibraryVersion": "2.0.0"},
        ]}
    ]
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [f1, f2]}
    result = source3.render_inputs(entry)
    assert result["parents"] == ["app@1.0.0", "other-app@2.0.0"]


def test_vulnerabilities_sorted_by_score_descending_with_unscored_last():
    high = _finding()
    high["vulnerability"] = {**high["vulnerability"], "name": "CVE-HIGH", "score": 9.8}
    zero = _finding()
    zero["vulnerability"] = {**zero["vulnerability"], "name": "CVE-ZERO", "score": 0.0}
    unscored_none = _finding()
    unscored_none["vulnerability"] = {**unscored_none["vulnerability"], "name": "CVE-NONE", "score": None}
    unscored_empty = _finding()
    unscored_empty["vulnerability"] = {**unscored_empty["vulnerability"], "name": "CVE-EMPTY", "score": ""}
    mid = _finding()
    mid["vulnerability"] = {**mid["vulnerability"], "name": "CVE-MID", "score": 5.0}

    entry = {
        "library": "lodash", "kind": "vulnerability",
        "findings": [mid, unscored_none, high, zero, unscored_empty],
    }
    result = source3.render_inputs(entry)
    names = [v["name"] for v in result["vulnerabilities"]]
    assert names[:3] == ["CVE-HIGH", "CVE-MID", "CVE-ZERO"]
    # unscored findings trail, in whatever relative order, but always last
    assert set(names[3:]) == {"CVE-NONE", "CVE-EMPTY"}
    scored = [v for v in result["vulnerabilities"] if v["score"] != ""]
    assert [v["score"] for v in scored] == [9.8, 5.0, 0.0]


def test_epss_maturity_and_reachability_are_read_from_threat_assessment_and_reachability():
    finding = _finding()
    finding["threatAssessment"] = {"epssPercentage": 0.5, "exploitCodeMaturity": "POC"}
    finding["reachability"] = "REACHABLE"
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [finding]}
    result = source3.render_inputs(entry)
    row = result["vulnerabilities"][0]
    assert row["epss"] not in ("", None)
    assert row["maturity"] not in ("", None)
    assert row["reachability"] not in ("", None)


def test_missing_threat_assessment_and_reachability_do_not_raise():
    finding = _finding()
    finding.pop("threatAssessment", None)
    finding.pop("reachability", None)
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [finding]}
    result = source3.render_inputs(entry)
    row = result["vulnerabilities"][0]
    assert row["epss"] == "-"
    assert row["maturity"] == "-"
    assert row["reachability"] == "-"


def test_vulnerability_row_shape_and_fix_fields():
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [_finding()]}
    result = source3.render_inputs(entry)
    row = result["vulnerabilities"][0]
    assert row["name"] == "CVE-2020-8203"
    assert row["severity"] == "high"
    assert row["description"] == "Prototype pollution."
    assert row["url"] == "https://nvd.nist.gov/vuln/CVE-2020-8203"
    assert row["fix_resolution"] == "Upgrade to 4.17.19"
    assert row["fix_type"] == "upgrade"
    assert row["fix_url"] == "https://example.com/fix"
    assert row["publish_date"] == "2020-07-15"


def test_entry_with_no_findings_returns_empty_vulnerabilities():
    entry = {"library": "lodash", "kind": "vulnerability", "findings": []}
    result = source3.render_inputs(entry)
    assert result["library"] == "lodash"
    assert result["vulnerabilities"] == []
    assert result["parents"] == []
    assert result["version"] == ""
    assert result["dependency_type"] == ""


def test_license_entry_with_no_component_attached_returns_only_the_library_name():
    """A license entry's violations carry no component, so with nothing attached every metadata
    field is blank. The metadata comes from entry["component"] instead -- see
    test_license_metadata.py. `vulnerabilities` and `parents` stay empty either way: a violation
    is not a finding."""
    entry = {
        "library": "some-lib",
        "kind": "license",
        "findings": [{"findingType": "LEGAL", "originName": "some-lib", "licenseName": "GPL"}],
    }
    result = source3.render_inputs(entry)
    assert result == {
        "library": "some-lib",
        "version": "",
        "description": "",
        "home_page": "",
        "dependency_type": "",
        "dependency_file": "",
        "library_path": "",
        "parents": [],
        "vulnerabilities": [],
    }


def test_missing_component_never_raises_and_yields_blanks():
    finding = _finding()
    finding.pop("component", None)
    entry = {"library": "lodash", "kind": "vulnerability", "findings": [finding]}
    result = source3.render_inputs(entry)
    assert result["version"] == ""
    assert result["description"] == ""
    assert result["home_page"] == ""
    assert result["dependency_file"] == ""
    assert result["library_path"] == ""


def test_malformed_entry_inputs_never_raise():
    assert source3.render_inputs({}) == {
        "library": "",
        "version": "",
        "description": "",
        "home_page": "",
        "dependency_type": "",
        "dependency_file": "",
        "library_path": "",
        "parents": [],
        "vulnerabilities": [],
    }
    assert source3.render_inputs({"library": "x", "kind": "vulnerability", "findings": [None, "not-a-dict"]}) == {
        "library": "x",
        "version": "",
        "description": "",
        "home_page": "",
        "dependency_type": "",
        "dependency_file": "",
        "library_path": "",
        "parents": [],
        "vulnerabilities": [],
    }
