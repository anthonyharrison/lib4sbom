import os
# import pytest

from lib4sbom.parser import SBOMParser


class TestParser:
    def test_parse_file(self):
        files = []
        for (dirpath, _, filenames) in os.walk('../samples'):
            files.extend([os.path.join(dirpath, x) for x in filenames])
        for (dirpath, _, filenames) in os.walk('./data'):
            files.extend([os.path.join(dirpath, x) for x in filenames])
            break
        for f in files:
            print(f)
            a = SBOMParser()
            a.parse_file(f)
            assert a.get_packages()

    def test_parse_string(self):
        files = []
        for (dirpath, _, filenames) in os.walk('../samples'):
            files.extend([os.path.join(dirpath, x) for x in filenames])
        for (dirpath, _, filenames) in os.walk('./data'):
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
