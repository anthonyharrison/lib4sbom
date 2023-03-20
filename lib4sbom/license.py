# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


import json
import os


class LicenseScanner:

    DEFAULT_LICENSE = "UNKNOWN"
    SPDX_LICENSE_VERSION = "3.20"

    def __init__(self):
        # Load licenses
        license_dir, filename = os.path.split(__file__)
        license_path = os.path.join(license_dir, "license_data", "spdx_licenses.json")
        licfile = open(license_path)
        self.licenses = json.load(licfile)
        # Set up list of license synonyms
        synonym_file = os.path.join(license_dir, "license_data", "license_synonyms.txt")
        self.license_synonym = {}
        self.synonym_setup(synonym_file, self.license_synonym)

    def synonym_setup(self, filename, data_list):
        with open(filename, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("#"):
                    # Comment so ignore
                    continue
                elif line.startswith("["):
                    license = line.replace("[", "").replace("]", "").strip()
                else:
                    # Store all synonyms in upper case
                    data_list[line.strip().upper()] = license

    def get_license_version(self):
        return self.SPDX_LICENSE_VERSION

    def check_synonym(self, license):
        # Look for synonyms. Check is done in uppercase to handle mixed case license identifiers
        return self.license_synonym.get(license.upper(),None)

    def find_license(self, license):
        # Search list of licenses to find match
        # Ignore non-SPDX licenses
        if license.upper() in ["NOASSERTION", "NONE"]:
            return license
        # Don't process SPDX user defined licenses which start with LicenseRef.
        if license.startswith("LicenseRef"):
            return license
        for lic in self.licenses["licenses"]:
            # Comparisons ignore case of provided license text
            if lic["licenseId"].lower() == license.lower():
                return lic["licenseId"]
            elif lic["name"].lower() == license.lower():
                return lic["licenseId"]
        # Look for synonyms
        license_id = self.check_synonym(license)
        
        return license_id if license_id is not None else self.DEFAULT_LICENSE

    def get_license_url(self, license_id):
        # Assume that license_id is a valid SPDX id
        if license_id != self.DEFAULT_LICENSE:
            for lic in self.licenses["licenses"]:
                # License URL is in the seeAlso field.
                # If multiple entries, just return first one
                if lic["licenseId"] == license_id:
                    return lic["seeAlso"][0]
        return None  # License n