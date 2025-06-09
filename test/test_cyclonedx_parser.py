import os

import pytest

from lib4sbom.cyclonedx.cyclonedx_parser import CycloneDXParser as test_module


class TestCcycloneDX_parser:
    def get_test_filepath(self, relpath):
        file_path = os.path.abspath(os.path.realpath(__file__))
        test_data_path = os.path.join(os.path.dirname(file_path), "data")
        return os.path.join(test_data_path, relpath)

    def test_parse(self):
        assert False

    def test_parse_cyclonedx_json(self):
        assert False

    def test_parse_cyclonedx_xml(self):
        test_parser = test_module()
        path = self.get_test_filepath('hadoop-aliyun-3.4.1-cyclonedx.xml')
        result = test_parser.parse(path)
        (
            cyclonedx_document,
            files,
            packages,
            relationships,
            vulnerabilities,
            services,
            licenses
        ) = result

        with open(path, "r", encoding="utf-8") as f:
            sbom_string = f.read()
        result = test_parser.parse(path, sbom_string)
        (
            cyclonedx_document,
            files,
            packages,
            relationships,
            vulnerabilities,
            services,
            licenses
        ) = result

    def test_parse_cyclonedx_multiple_licenses_json(self):
        test_parser = test_module()
        path = self.get_test_filepath("testapp2.json")
        result1 = test_parser.parse(path)
        with open(path, "r", encoding="utf-8") as f:
            sbom_string = f.read()
        result2 = test_parser.parse(path, sbom_string)
        for result in [result1, result2]:
            (
                cyclonedx_document,
                files,
                packages,
                relationships,
                vulnerabilities,
                services,
            ) = result
            multi_license = None
            for p, v in packages:
                if p == "multi-license":
                    multi_license = packages[(p, v)]
                    break

            assert multi_license is not None, "Did not find expected package multi-license"
            assert "licenselist" in multi_license
            license_list = multi_license["licenselist"]
            assert len(license_list) == 2
            assert license_list[0]["license"]["id"] == "MIT"
            assert license_list[1]["license"]["id"] == "Apache-2.0"
