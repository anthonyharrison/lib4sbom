from lib4sbom.parser import SBOMParser
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput

test_parser = SBOMParser()
test_parser.parse_file("test/data/test_sbom.spdx")
test_generator = SBOMGenerator(False, sbom_type="spdx", format="json")
test_generator.generate("TestApp", test_parser.get_sbom())
sbom_output = SBOMOutput(output_format="json")
sbom_output.generate_output(test_generator.get_sbom())


