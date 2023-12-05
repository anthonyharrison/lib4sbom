# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


import json
import os


class LicenseScanner:
    DEFAULT_LICENSE = "UNKNOWN"
    SPDX_LICENSE_VERSION = "3.22"

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
        # Look for synonyms. Check done in uppercase to handle mixed case license identifiers
        return self.license_synonym.get(license.upper(), None)

    def find_license_id(self, license):
        # Search list of SPDX licenses to find match
        # Handle special cases
        if len(license) == 0:
            return self.DEFAULT_LICENSE
        elif license.upper() in ["NOASSERTION", self.DEFAULT_LICENSE]:
            # Ignore non-SPDX licenses
            return self.DEFAULT_LICENSE
        elif license.upper() == "NONE":
            # Maintain value
            return license.upper()
        elif license.startswith("LicenseRef"):
            # Don't process SPDX user defined licenses
            return license
        # Deprecated license ids are still valid
        if self.deprecated(license):
            return license
        # Look for synonyms
        license_id = self.check_synonym(license)
        if license_id is not None:
            return license_id
        for lic in self.licenses["licenses"]:
            # Comparisons ignore case of provided license text
            if lic["licenseId"].lower() == license.lower():
                return lic["licenseId"]
            elif lic["name"].lower() == license.lower():
                return lic["licenseId"]
        return self.DEFAULT_LICENSE

    def get_license_url(self, license_id):
        # Assume that license_id is a valid SPDX id
        if license_id != self.DEFAULT_LICENSE:
            for lic in self.licenses["licenses"]:
                # License URL is in the seeAlso field.
                # If multiple entries, just return first one
                if lic["licenseId"] == license_id:
                    return lic["seeAlso"][0]
        return None  # License not found

    def osi_approved(self, license_id):
        # Assume that license_id is a valid SPDX id
        if license_id != self.DEFAULT_LICENSE:
            for lic in self.licenses["licenses"]:
                if lic["licenseId"] == license_id:
                    return lic["isOsiApproved"]
        return False  # License not found

    def deprecated(self, license_id):
        # Assume that license_id is a valid SPDX id
        if license_id != self.DEFAULT_LICENSE:
            for lic in self.licenses["licenses"]:
                if lic["licenseId"] == license_id and lic["isDeprecatedLicenseId"]:
                    return True
        return False  # License not found

    # License expression processing

    def _expression_split(self, expression):
        # Split expression into a list using words in keyword list as separators
        boolean_operator = ["AND", "OR"]
        result = []
        working = expression.replace("(", "").replace(")", "").split(" ")
        word = ""
        for item in working:
            if item.upper() in boolean_operator:
                # Store word in list
                if word not in result:
                    result.append(word)
                word = ""
            elif len(word) > 0:
                word = word + " " + item
            else:
                word = item
        # Store last word if available
        if len(word) > 0:
            if word not in result:
                result.append(word)
        return result

    def find_license(self, license_expression):
        # Multiple licenses can be specified and connected using boolean logic.
        # This will preserve any brackets and boolean operators included in the expression
        # Ensure case of operators is uppercase
        updated_expression = (
            license_expression.replace(" or ", " OR ")
            .replace(" Or ", " OR ")
            .replace(" and ", " AND ")
            .replace(" And ", " AND ")
            .replace("MIT/Apache-2.0", "MIT OR Apache-2.0")
            .replace("Apache-2.0/MIT", "Apache-2.0 OR MIT")
            .replace("Unlicense/MIT", "Unlicense OR MIT")
            .replace("MIT/Unlicense", "MIT OR Unlicense")
        )
        # Remove brackets and split into elements (separated by boolean operators)
        license_information = self._expression_split(updated_expression)
        # Now process license information and build up list of valid licenses
        license_data = []
        for license in license_information:
            # Assume we have a license!
            validated_license = self.find_license_id(license)
            license_data.append(validated_license)
            # Update expression if necessary if valid license found
            if validated_license not in [self.DEFAULT_LICENSE, "NONE"]:
                updated_expression = updated_expression.replace(
                    license, validated_license
                )
        # Return expression if all licenses are valid
        return (
            "NOASSERTION"
            if len(updated_expression) == 0 or self.DEFAULT_LICENSE in license_data
            else updated_expression
        )

    def license_expression(self, expression):
        # Determine if license expression contains multiple elements
        return len(self._expression_split(expression)) > 1
