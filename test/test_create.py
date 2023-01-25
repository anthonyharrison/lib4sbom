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
sbom_packages[my_package.get_name()] = my_package.get_package()
my_package.initialise()
my_package.set_name("tomcat")
my_package.set_version("9.0.46")
my_package.set_supplier("organisation","apache")
my_package.set_licensedeclared("Apache-2.0")
sbom_packages[my_package.get_name()] = my_package.get_package()
# Create file
sbom_files = {}
# Generate SBOM
#
my_sbom = SBOM()
my_sbom.add_packages(sbom_packages)
my_sbom.add_files(sbom_files)
print(my_sbom.get_sbom())
#
#
test_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
test_generator.generate("TestApp", my_sbom.get_sbom())
sbom_output = SBOMOutput(output_format="json")
sbom_output.generate_output(test_generator.get_sbom())


