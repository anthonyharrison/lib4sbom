# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Parse a SBOM file extracting package information from a PURL record (if available) or package data

import sys

from packageurl import PackageURL

from lib4sbom.generator import SBOMGenerator
from lib4sbom.parser import SBOMParser
from lib4sbom.data.identifier import SBOMIdentifier

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file(sys.argv[1])
modules = []
packages = [x for x in test_parser.get_sbom()["packages"].values()]
for package in packages:
    purl_found = False
    ext_ref = package.get("externalreference")
    if ext_ref != None:
        for ref in ext_ref:
            if ref[1] == "purl":
                # Process purl identifier
                purl_validator = SBOMIdentifier(ref[2])
                is_valid = purl_validator.validate()
                fixed_purl = purl_validator.fix()
                purl_errors = purl_validator.get_errors()
                #print (f"Validating: {ref[2]}")
                #print (f"\tValid: {is_valid}")
                if len(purl_errors) > 0:
                    print (f"Invalid PURL: {ref[2]}")
                    for error in purl_errors:
                        print (f"\t Error: {error}")
                    if len(fixed_purl) > 0:
                        print (f"\t Fixed: {fixed_purl}")
                elif fixed_purl != ref[2]:
                    print (f"Purl mismatch: {[ref[2]]} {fixed_purl}")
                purl_info = PackageURL.from_string(ref[2]).to_dict()
                # print (purl_info)
                if "version" in purl_info:
                    modules.append([purl_info["name"], purl_info["version"]])
                else:
                    modules.append([purl_info["name"], "UKNOWN"])
                purl_found = True
    if not purl_found:
        if "version" in package:
            modules.append([package["name"], package["version"]])
        else:
            modules.append([package["name"], "UNKNOWN"])

# for module in modules:
#     print (module)

# Set up SPDX-JSON generator
test_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Generate sbom in JSON format to console (default)
test_generator.generate("TestApp", test_parser.get_sbom(), filename="testapp.json")
