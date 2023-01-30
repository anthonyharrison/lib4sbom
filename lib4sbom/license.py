# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


import json
import os


class LicenseScanner:

    APACHE_SYNOYMNS = [
        "Apache Software License",
        "Apache License, Version 2.0",
        "Apache 2.0",
        "Apache_2.0",
        "Apache 2",
    ]
    DEFAULT_LICENSE = "UNKNOWN"
    SPDX_LICENSE_VERSION = "3.18"

    def __init__(self):
        # Load licenses
        license_dir, filename = os.path.split(__file__)
        license_path = os.path.join(license_dir, "license_data", "spdx_licenses.json")
        licfile = open(license_path)
        self.licenses = json.load(licfile)

    def get_license_version(self):
        return self.SPDX_LICENSE_VERSION

    def check_synoymn(self, license, synoymns, value):
        return value if license in synoymns else None

    def find_license(self, license):
        # Search list of licenses to find match
        if license in ["NOASSERTION", "NONE"]:
            return license
        for lic in self.licenses["licenses"]:
            # Comparisons ignore case of provided license text
            if lic["licenseId"].lower() == license.lower():
                return lic["licenseId"]
            elif lic["name"].lower() == license.lower():
                return lic["licenseId"]
        license_id = self.check_synoymn(license, self.APACHE_SYNOYMNS, "Apache-2.0")
        return license_id if license_id is not None else self.DEFAULT_LICENSE

    def get_license_url(self, license_id):
        # Assume that license_id is a valid SPDX id
        if license_id != self.DEFAULT_LICENSE:
            for lic in self.licenses["licenses"]:
                # License URL is in the seeAlso field.
                # If multiple entries, just return first one
                if lic["licenseId"] == license_id:
                    return lic["seeAlso"][0]
        return None  # License not found
