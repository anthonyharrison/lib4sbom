# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create an OpenChain compliant SBOM

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

# Create package
sbom_packages = {}

my_package = SBOMPackage()
my_package.set_name("pyyaml")
my_package.set_version("6.0.1")
my_package.set_type("Library")
my_package.set_supplier("person", "Kirill Simonov (xi@resolvent.net)")
my_package.set_downloadlocation("https://pypi.org/project/PyYAML/")
my_package.set_homepage("https://pyyaml.org/")
my_package.set_summary("YAML parser and emitter for Python")
my_package.set_licensedeclared("MiT")
my_package.set_licenseconcluded("MIt license")
my_package.set_checksum("SHA256", "d858aa552c999bc8a8d57426ed01e40bef403cd8ccdd0fc5f6f04a00414cac2a")
my_package.set_purl("pkg:pypi/pyyaml@6.0.1")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="spdx")
my_sbom.set_version("SPDX-2.3")
my_doc = SBOMDocument()
my_doc.set_value("lifecycle", "build")
# Set the organisation creating SBOM. Can also set env variable SBOM_ORGANIZATION
my_doc.set_metadata_supplier("Acme Inc.")
my_sbom.add_document(my_doc.get_document())
my_sbom.add_packages(sbom_packages)
#
my_generator = SBOMGenerator(True, sbom_type="spdx", format="tag")
# Will be displayed on console
my_generator.generate("OpenChain", my_sbom.get_sbom())
