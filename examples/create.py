# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX SBOM in JSON format

from lib4sbom.sbom import SBOM
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput

from lib4sbom.data.package import SBOMPackage

# Create packages
sbom_packages = {}
my_package = SBOMPackage()
my_package.set_name("glibc")
my_package.set_version("2.15")
my_package.set_supplier("organisation","gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_supplier("organisation","gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
my_package.initialise()
my_package.set_name("tomcat")
my_package.set_version("9.0.46")
my_package.set_supplier("organisation","apache")
my_package.set_licensedeclared("Apache-2.0")
sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
# Duplicated data
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_supplier("organisation","gnu")
my_package.set_licensedeclared("GPL3")
#### This has no affect as this is a duplicated package (same name and version)
sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
# Generate SBOM
my_sbom = SBOM()
my_sbom.add_packages(sbom_packages)
#print(my_sbom.get_sbom())
#
#
my_generator = SBOMGenerator(False, sbom_type="spdx", format="json")
# Will be displayed on console
my_generator.generate("TestApp", my_sbom.get_sbom())

# Send to file



