# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to parse a SBOM and
### produce a summary of its contents

import sys
from lib4sbom.parser import SBOMParser
from lib4sbom.data.document import SBOMDocument


test_parser = SBOMParser()
# Load SBOM
try:
    test_parser.parse_file(sys.argv[1])

    # What type of SBOM
    document = SBOMDocument()
    print (test_parser.get_document())
    document.copy_document(test_parser.get_document())

    packages = test_parser.get_packages()
    files = test_parser.get_files()
    print ("Summary")
    print ("=" * len("summary"))
    print (f"SBOM Type    {document.get_type()}")
    print (f"Version      {document.get_version()}")
    print (f"Name         {document.get_name()}")
    print ()
    print (f"Files        {len(files)}")
    for file in files:
        print (f"{file['name']:30} - {file.get('type','NOT DEFINED'):20}")
    print (f"\nPackages     {len(packages)}")
    print (f"\n{'Name':30} {'Version':15} {'Type':20}")
    print ("-" * 70)
    for package in packages:
        print (f"{package['name']:30} {package.get('version','MISSING'):15} {package['type']:20}")

except FileNotFoundError:
    print (f"{sys.argv[1]} not found")


