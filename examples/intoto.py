import sys

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.service import SBOMService
from lib4sbom.parser import SBOMParser

sbom_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
sbom_parser.parse_file(sys.argv[1])
document = SBOMDocument()
document.copy_document(sbom_parser.get_document())
sbom_type = document.get_type()
modules = []
for package in sbom_parser.get_packages():
    product = package.get("name", "")
    version = package.get("version", "")
    type = package.get("type", None)
    vendor = package.get("supplier", "")
    # Concluded licence takes preference over declared licence
    license = package.get("licenseconcluded", "NOASSERTION")
    if license == "NOASSERTION":
        # See if there is a declared licence
        print (f"Looking for Declared licence for {product} {version}")
        license = package.get("licensedeclared", "NOASSERTION")
    modules.append(
        {
            "vendor": vendor,
            "product": product,
            "version": version,
            "license": license,
            "type": type,
        }
    )
for m in modules:
    print (m)