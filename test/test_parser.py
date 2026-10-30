import json
import os
import tempfile

import pytest

from lib4sbom.exception import SBOMParserException
from lib4sbom.parser import SBOMParser


class TestParser:
    def test_parse_file(self):
        files = []
        for dirpath, _, filenames in os.walk("../samples"):
            files.extend([os.path.join(dirpath, x) for x in filenames])
        for dirpath, _, filenames in os.walk("./data"):
            files.extend([os.path.join(dirpath, x) for x in filenames])
            break
        for f in files:
            print(f)
            a = SBOMParser()
            a.parse_file(f)
            assert a.get_packages()

    def test_parse_file_no_filename_extension(self):
        # SBOM files without a recognised filename extension are
        # identified from the file contents
        test_dir = os.path.dirname(os.path.abspath(__file__))
        formats = [
            (os.path.join(test_dir, "data", "testapp.spdx.json"), "spdx", "json"),
            (
                os.path.join(
                    test_dir, "data", "CDX", "software_component_use_case.cdx.json"
                ),
                "cyclonedx",
                "json",
            ),
            (os.path.join(test_dir, "data", "cyclonedx_test.xml"), "cyclonedx", "xml"),
            (os.path.join(test_dir, "data", "spdx_test.spdx"), "spdx", "tag"),
            (os.path.join(test_dir, "data", "testapp2.spdx.yaml"), "spdx", "yml"),
            (
                os.path.join(test_dir, "..", "samples", "spdx.spdx.rdf"),
                "spdx",
                "rdf",
            ),
        ]
        for file_name, sbom_type, sbom_format in formats:
            with open(file_name, "r", encoding="utf-8") as sbom_file:
                sbom_string = sbom_file.read()
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix="", delete=False
            ) as test_file:
                test_file.write(sbom_string)
                test_filename = test_file.name
            try:
                sbom_parser = SBOMParser()
                sbom_parser.parse_file(test_filename)
                assert sbom_parser.get_type() == sbom_type
                assert sbom_parser.get_format() == sbom_format
                assert sbom_parser.get_packages()
            finally:
                os.unlink(test_filename)

    def test_parse_file_invalid_content_no_filename_extension(self):
        # Content which is not an SBOM is reported with SBOMParserException
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix="", delete=False
        ) as test_file:
            test_file.write("This is not a SBOM file")
            test_filename = test_file.name
        try:
            sbom_parser = SBOMParser()
            with pytest.raises(SBOMParserException):
                sbom_parser.parse_file(test_filename)
        finally:
            os.unlink(test_filename)

    def test_parse_file_jsonld_no_filename_extension(self):
        # SPDX 3.x JSON-LD content in a file without a recognised filename
        # extension is identified from the file contents
        jsonld_content = json.dumps(
            {
                "@context": "https://spdx.org/rdf-3.0/spdx-context.jsonld",
                "@graph": [
                    {
                        "type": "SpdxDocument",
                        "spdxId": "https://spdx.org/spdxdocs/spdx-test-document",
                        "name": "SPDX-Test-Document",
                    },
                    {
                        "type": "software_Package",
                        "spdxId": "https://spdx.org/spdxdocs/spdx-test-package-1",
                        "name": "test-package-1",
                    },
                ],
            }
        )
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix="", delete=False
        ) as test_file:
            test_file.write(jsonld_content)
            test_filename = test_file.name
        try:
            sbom_parser = SBOMParser()
            sbom_parser.parse_file(test_filename)
            assert sbom_parser.get_type() == "spdx"
            assert sbom_parser.get_format() == "jsonld"
            assert sbom_parser.get_packages()
        finally:
            os.unlink(test_filename)

    def test_parse_string(self):
        files = []
        for dirpath, _, filenames in os.walk("../samples"):
            files.extend([os.path.join(dirpath, x) for x in filenames])
        for dirpath, _, filenames in os.walk("./data"):
            files.extend([os.path.join(dirpath, x) for x in filenames])
            break
        for f in files:
            print(f)
            a = SBOMParser()
            with open(f, "r", encoding="utf-8") as f:
                sbom_string = f.read()
                a.parse_string(sbom_string)
            assert a.get_packages()

    def test_get_type(self):
        assert False

    def test_get_files(self):
        assert False

    def test_get_packages(self):
        assert False

    def test_get_relationships(self):
        assert False
