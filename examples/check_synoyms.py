import json
# Check SPDX license file and check synoyms
license_file = "lib4sbom/license_data/spdx_licenses.json"
synonym_file = "lib4sbom/license_data/license_synonyms.txt"
# Load license file
licenses_data = json.load(open(license_file, "r", encoding="utf-8"))
data_list = {}
with open(synonym_file, "r", encoding="utf-8") as f:
    lines = f.readlines()
    for line in lines:
        if line.startswith("#"):
            # Comment so ignore
            continue
        elif line.startswith("["):
            license = line.replace("[", "").replace("]", "").strip()
        else:
            # Store all synonyms in upper case
            license_name = line.strip().upper()
            data_list[license_name] = license
            for license_record in licenses_data["licenses"]:
                if license_record.get("name").upper() == license_name:
                    print (f"[{license}] - {license_name} not required - NAME")
                    break
                elif license_record.get("licenseId").upper() == license_name:
                    print (f"[{license}] - {license_name} not required - ID")
                    break

