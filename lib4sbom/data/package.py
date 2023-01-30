# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import string

from lib4sbom.license import LicenseScanner


class SBOMPackage:
    def __init__(self):
        self.package = {}
        self.license = LicenseScanner()

    def initialise(self):
        self.package = {}

    def set_name(self, name):
        self.package["name"] = name

    def set_id(self, id):
        self.package["id"] = id

    def set_type(self, type):
        self.package["type"] = type

    def set_version(self, version):
        self.package["version"] = self._semantic_version(version)
        my_id = self.package.get("id")
        my_name = self.get_name()
        if my_id is None and my_name is not None:
            self.set_id(self.get_name() + "_" + str(self.package["version"]))

    def set_supplier(self, type, name):
        self.package["supplier_type"] = type.strip()
        self.package["supplier"] = name

    def set_originator(self, type, name):
        self.package["originator_type"] = type.strip()
        self.package["originator"] = name

    def set_downloadlocation(self, location):
        self.package["downloadlocation"] = location

    def set_filename(self, filename):
        self.package["filename"] = filename

    def set_homepage(self, page):
        self.package["homepage"] = page

    def set_sourceinfo(self, info):
        self.package["sourceinfo"] = info

    def set_filesanalysis(self, analysis):
        self.package["filesanalysis"] = analysis

    def set_checksum(self, type, value):
        # Only store valid checksums
        if self._valid_checksum(value):
            # Allow multiple entries
            checksum_entry = [type.strip(), value.lower()]
            if "checksum" in self.package:
                self.package["checksum"].append(checksum_entry)
            else:
                self.package["checksum"] = [checksum_entry]

    def set_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.package:
            self.package["property"].append(property_entry)
        else:
            self.package["property"] = [property_entry]

    def set_licenseconcluded(self, license):
        self.package["licenseconcluded"] = license

    def set_licensedeclared(self, license):
        self.package["licensedeclared"] = license

    def set_licensecomments(self, comment):
        self.package["licensecomments"] = comment

    def set_licenseinfoinfiles(self, license_info):
        # Validate license
        license_id = self.license.find_license(license_info)
        # Only include if valid license
        if license_id != "UNKNOWN":
            if "licenseinfoinfile" in self.package:
                self.package["licenseinfoinfiles"].append(license_info)
            else:
                self.package["licenseinfoinfiles"] = [license_info]

        self.package["licenseinfoinfiles"] = license_info

    def set_externalreference(self, category, type, locator):
        # Allow multiple entries
        reference_entry = [category, type.strip(), locator]
        if "externalreference" in self.package:
            self.package["externalreference"].append(reference_entry)
        else:
            self.package["externalreference"] = [reference_entry]

    def set_copyrighttext(self, text):
        self.package["copyrighttext"] = text

    def set_comment(self, comment):
        self.package["comment"] = comment

    def set_summary(self, summary):
        self.package["summary"] = summary

    def set_description(self, description):
        self.package["description"] = description

    def set_value(self, key, value):
        self.package[key] = value

    def get_package(self):
        return self.package

    def get_value(self, attribute):
        return self.package.get(attribute, None)

    def debug_package(self):
        print("OUTPUT:", self.package)

    def show_package(self):
        for key in self.package:
            print(f"{key}    : {self.package[key]}")

    def copy_package(self, package_info):
        for key in package_info:
            self.set_value(key, package_info[key])

    def get_name(self):
        return self.get_value("name")

    def _semantic_version(self, version):
        return version.split("-")[0] if "-" in version else version

    def _valid_checksum(self, value):
        # Only allow valid hex or decimal digits
        return all(c in string.hexdigits for c in value.lower())
