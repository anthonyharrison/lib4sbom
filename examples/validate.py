from lib4sbom.validator import SBOMValidator
import sys

sv = SBOMValidator(sbom_type="auto", debug=True)
filename = sys.argv[1]
try:
    check = sv.validate_file(filename)
    for sbom_type in ["SPDX", "CycloneDX"]:
        if check.get(sbom_type) == "Unknown":
            print(f"Unable to determine if {filename} is a valid SBOM: {check}")
        elif check.get(sbom_type) == False:
            print(f"{filename} is not a valid SBOM: {check}")
        elif check.get(sbom_type) is not None:
            print (f"{filename} is a valid SBOM: {check}")
except FileNotFoundError:
    print (f"{filename} not found.")

