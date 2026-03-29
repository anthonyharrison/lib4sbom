# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to convert an SBOM in
### SPDX 3 JSON-LD format to a SPDX SBOM in SPDX 2 JSON format

### Param1 SPDX 3 Input filename
### Param2 SPDX 2 Output filename

import os
import sys

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

if len(sys.argv) != 3:
    print("usage: python convert3spdx2.py SPDX3file SPDX2file")
    sys.exit(1)

# Check SPDX3 enabled
if os.getenv("LIB4SBOM_SPDX3") is not None:
    print ("Please unset environment variable LIB4SBOM_SPDX3 to disable SPDX3 generation")
else:
    # Set up SBOM parser
    test_parser = SBOMParser()
    # Load SBOM - will autodetect SBOM type
    test_parser.parse_file(sys.argv[1])
    # Set up SPDX-JSON generator
    test_generator = SBOMGenerator(False, sbom_type="spdx", format="json")
    # Generate sbom in JSON format
    test_generator.generate("TestApp", test_parser.get_sbom(), send_to_output=False)
    sbom_output = SBOMOutput(filename=sys.argv[2], output_format="json")
    sbom_output.generate_output(test_generator.get_sbom())
