# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to convert an SBOM in
### SPDX 2 format to a SPDX SBOM in SPDX 3 JSON-LD format

### Param1 SPDX 2 Input filename
### Param2 SPDX 3 Output filename

import os
import sys

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

if len(sys.argv) != 3:
    print("usage: python convert2spdx3.py SPDX2file SPDX3file")
    sys.exit(1)

# Check SPDX3 enabled
if os.getenv("LIB4SBOM_SPDX3") is None:
    print ("Please set environment variable LIB4SBOM_SPDX3=True to enable SPDX3 generation")
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
