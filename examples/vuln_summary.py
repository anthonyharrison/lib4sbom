# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to parse a SBOM and
### produce a summary of the vulnerabilities

import sys

from lib4sbom.data.document import SBOMDocument
from lib4sbom.parser import SBOMParser

test_parser = SBOMParser()
# Load SBOM
try:
    test_parser.parse_file(sys.argv[1])

    # What type of SBOM
    document = SBOMDocument()
    document.copy_document(test_parser.get_document())

    vulnerabilities = test_parser.get_vulnerabilities()
    print("Summary")
    print("=" * len("summary"))
    print(f"SBOM Type    {document.get_type()}")
    print(f"Version      {document.get_version()}")
    print(f"Name         {document.get_name()}")
    print(f"\nVulnerabilities    {len(vulnerabilities)}")
    if len(vulnerabilities) > 0:
        print("-" * 70)
        for vuln in vulnerabilities:
            print(f"{vuln['id']} {vuln['source-name']}")

except FileNotFoundError:
    print(f"{sys.argv[1]} not found")
