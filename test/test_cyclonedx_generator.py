from lib4sbom.cyclonedx.cyclonedx_generator import CycloneDXGenerator as test_module


class TestCycloneDXGenerator:
    def test_store(self):
        assert False

    def test_getBOM(self):
        assert False

    def test_generateTime(self):
        assert False

    def test_generateDocumentHeader(self):
        assert False

    def test_generateJSONDocumentHeader(self):
        assert False

    def test_generateXMLDocumentHeader(self):
        assert False

    def test_generateRelationship(self):
        assert False

    def test_generateComponent(self):
        assert False

    def test_generateJSONComponent(self):
        assert False

    def test_generateXMLComponent(self):
        assert False

    def test_generate_vulnerability_data_affects(self):
        # Version parsed from an affects entry is preserved in generated
        # vulnerabilities
        generator = test_module()
        component_data = {
            "type": "application",
            "supplier": None,
            "version": None,
            "bom-ref": None,
            "timestamp": "2026-01-01T00:00:00Z",
            "creator": None,
            "lifecycle": None,
            "distribution": None,
        }
        generator.generateDocumentHeader("testapp", component_data)
        vulnerability = {
            "id": "CVE-2026-0001",
            "status": "exploitable",
            "affects": [
                {"ref": "component-a", "version": "1.0"},
                {"ref": "component-b", "version": None},
            ],
        }
        generator.generate_vulnerability_data([vulnerability])
        vulnerabilities = generator.getBOM()["vulnerabilities"]
        assert len(vulnerabilities) == 1
        affects = vulnerabilities[0]["affects"]
        assert len(affects) == 2
        assert affects[0]["ref"] == "component-a"
        assert affects[0]["versions"] == [{"version": "1.0", "status": "affected"}]
        assert affects[1]["ref"] == "component-b"
        assert affects[1]["versions"] == [{"version": None, "status": "affected"}]
