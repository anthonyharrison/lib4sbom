# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to read an SPDX SBOM in tag value
### format to a SPDX SBOM in JSON format (and shown on console) and

import sys

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file(sys.argv[1])
# Set up SPDX-JSON generator
test_generator = SBOMGenerator(False, sbom_type=test_parser.get_type(), format="json")
# Generate sbom in JSON format to console (default)
test_generator.generate("TestApp", test_parser.get_sbom())
