import json
import os

from lib4sbom.cyclonedx.cyclonedx_parser import CycloneDXParser as test_module


class TestCycloneDX_parser:
    def get_test_filepath(self, relpath):
        file_path = os.path.abspath(os.path.realpath(__file__))
        test_data_path = os.path.join(os.path.dirname(file_path), "data")
        return os.path.join(test_data_path, relpath)

    def _read_test_file(self, relpath):
        path = self.get_test_filepath(relpath)
        with open(path, "r", encoding="utf-8") as sbom_file:
            return sbom_file.read()

    def test_parse(self):
        assert False

    def test_parse_cyclonedx_json(self):
        test_parser = test_module()
        sbom_string = self._read_test_file("testapp2.json")
        result = test_parser.parse(sbom_string)
        assert len(result["packages"]) > 0

    def test_parse_cyclonedx_xml(self):
        test_parser = test_module()
        sbom_string = self._read_test_file("hadoop-aliyun-3.4.1-cyclonedx.xml")
        result = test_parser.parse(sbom_string)
        assert len(result["packages"]) > 0

    def test_parse_cyclonedx_multiple_licenses_json(self):
        test_parser = test_module()
        sbom_string = self._read_test_file("testapp2.json")
        result = test_parser.parse(sbom_string)
        multi_license = None
        for name, version in result["packages"]:
            if name == "multi-license":
                multi_license = result["packages"][(name, version)]
                break
        assert multi_license is not None, "Did not find expected package multi-license"
        assert "licenselist" in multi_license
        license_list = multi_license["licenselist"]
        assert len(license_list) == 2
        assert license_list[0]["id"] == "MIT"
        assert license_list[1]["id"] == "Apache-2.0"

    def test_parse_cyclonedx_multiple_affects_json(self):
        # A vulnerability with multiple affects entries records every affected
        # component (issue #99)
        test_parser = test_module()
        sbom_string = self._read_test_file("one-vuln-two-affects.cdx.json")
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        record = vulnerabilities[0]
        assert record["id"] == "CVE-2019-12384"
        assert record["status"] == "not_affected"
        assert record["justification"] == "code_not_present"
        bom_ref_base = (
            "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#"
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@"
        )
        affects = record["affects"]
        assert len(affects) == 2
        assert sorted(entry["ref"] for entry in affects) == sorted(
            bom_ref_base + version for version in ("2.9.8", "2.9.9")
        )

    def test_parse_cyclonedx_affects_layouts_equivalent_json(self):
        # One vulnerability object with multiple affects entries provides the
        # same affected component data as one vulnerability object per affected
        # component, each with a single affects entry (issue #99)
        test_parser = test_module()
        affected = []
        for test_file in (
            "one-vuln-two-affects.cdx.json",
            "two-vulns-one-affects.cdx.json",
        ):
            sbom_string = self._read_test_file(test_file)
            result = test_parser.parse(sbom_string)
            affected.append(
                sorted(
                    (record["id"], entry["ref"], entry["version"])
                    for record in result["vulnerabilities"]
                    for entry in record.get("affects", [])
                )
            )
        assert len(affected[0]) == 2
        assert affected[0] == affected[1]

    def test_parse_cyclonedx_affects_versions_list_json(self):
        # The specification defines affects[].versions as a list of version
        # objects, with one affects entry per affected version
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [
                            {
                                "ref": "component-a",
                                "versions": [{"version": "1.0"}, {"version": "2.0"}],
                            },
                        ],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        affects = vulnerabilities[0]["affects"]
        assert len(affects) == 2
        assert sorted(entry["version"] for entry in affects) == ["1.0", "2.0"]
        for entry in affects:
            assert entry["ref"] == "component-a"

    def test_parse_cyclonedx_affects_versions_dict_json(self):
        # The historic dict form of affects[].versions is still supported
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [
                            {"ref": "component-a", "versions": {"version": "1.5"}},
                        ],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["affects"] == [
            {"ref": "component-a", "version": "1.5"}
        ]

    def test_parse_cyclonedx_affects_no_ref_json(self):
        # ref is optional in the specification, an affects entry without a ref
        # is skipped and does not inherit the ref of a previous entry
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "affects": [
                            {"ref": "component-a"},
                            {"versions": {"version": "9.9"}},
                            {"ref": "component-b"},
                        ],
                    }
                ],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["affects"] == [
            {"ref": "component-a", "version": None},
            {"ref": "component-b", "version": None},
        ]

    def test_parse_cyclonedx_vulnerability_no_affects_json(self):
        # A vulnerability without an affects entry still produces a record
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [{"id": "CVE-2026-0001"}],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2026-0001"
        assert "affects" not in vulnerabilities[0]

    def test_parse_cyclonedx_vulnerability_empty_affects_json(self):
        # A vulnerability with an empty affects list still produces a record
        sbom_string = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [{"id": "CVE-2026-0001", "affects": []}],
            }
        )
        test_parser = test_module()
        result = test_parser.parse(sbom_string)
        vulnerabilities = result["vulnerabilities"]
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2026-0001"
        assert "affects" not in vulnerabilities[0]
