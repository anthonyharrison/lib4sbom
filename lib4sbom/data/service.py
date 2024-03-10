# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re
import string

from lib4sbom.license import LicenseScanner

class SBOMService:
    def __init__(self):
        self.service = {}
        self.license = LicenseScanner()

    def _text(self, text_item):
        return text_item.replace("<text>", "").replace("</text>", "")

    def _url_valid(self, url):
        url_pattern = (
            "(http:\\/\\/www\\.|https:\\/\\/www\\.|http:\\/\\/|https:\\/\\/|ssh:\\/\\/|git:\\/\\/|svn:\\/\\/|sftp:"
            "\\/\\/|ftp:\\/\\/)?[a-z0-9]+([\\-\\.]{1}[a-z0-9]+){0,100}\\.[a-z]{2,5}(:[0-9]{1,5})?(\\/.*)?"
        )
        # Simple check to catch multiple URLs
        if " " in url:
            return False
        check_url = re.match(url_pattern, url)
        if check_url is None:
            # No match
            return False
        # Check URL is fully matched
        return check_url.group(0) == url

    def initialise(self):
        self.service = {}

    def set_name(self, name):
        self.service["name"] = name

    def set_id(self, id):
        self.service["id"] = id

    def set_flow_type(self, type):
        # Handle all types as upper case.
        flow_type = type.upper().replace("_", "-").strip()
        if flow_type in [
            "INBOUND",
            "OUTBOUND",
            "BI-DIRECTIONAL",
            "UNKNOWN",
        ]:
            self.service["flow_type"] = service_type
        else:
            self.service["flow_type"] = "UNKNOWN"

    def set_version(self, version):
        self.service["version"] = self._semantic_version(version)
        my_id = self.service.get("id")
        my_name = self.get_name()
        if my_id is None and my_name is not None:
            self.set_id(self.get_name() + "_" + str(self.service["version"]))

    def _validate_provider_type(self, type):
        provider_type = type.lower().strip()
        if supplier_type in [
            "person",
            "organization",
        ]:
            return supplier_type.capitalize()
        if supplier_type == "author":
            return "Person"
        if supplier_type == "unknown":
            return "UNKNOWN"
        return "Organization"

    def set_supplier(self, type, name):
        if len(name) > 0:
            self.service["supplier_type"] = self._validate_supplier_type(type.strip())
            self.service["supplier"] = name

    def set_originator(self, type, name):
        if len(name) > 0:
            self.service["originator_type"] = self._validate_supplier_type(type.strip())
            self.service["originator"] = name

    def set_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.service:
            self.service["property"].append(property_entry)
        else:
            self.service["property"] = [property_entry]

    def set_licenseconcluded(self, license):
        self.service["licenseconcluded"] = license

    def set_licensedeclared(self, license, name=None):
        self.service["licensedeclared"] = license
        if name is not None:
            # Use name if not SPDX license. license is then assumed to be the license text
            self.service["licensename"] = name

    def set_licensecomments(self, comment):
        self.service["licensecomments"] = self._text(comment)

    def set_licenseinfoinfiles(self, license_info):
        # Validate license
        license_id = self.license.find_license(license_info)
        # Only include if valid license
        if license_id != "UNKNOWN":
            if "licenseinfoinfile" in self.service:
                self.service["licenseinfoinfiles"].append(license_info)
            else:
                self.service["licenseinfoinfiles"] = [license_info]

        self.service["licenseinfoinfiles"] = license_info

    def set_attribution(self, value):
        # Allow multiple entries
        attribution_entry = [value]
        if "attribution" in self.service:
            self.service["attribution"].append(attribution_entry)
        else:
            self.service["attribution"] = [attribution_entry]

    def set_externalreference(self, category, type, locator):
        # Allow multiple entries
        reference_entry = [category, type.strip(), locator]
        if "externalreference" in self.service:
            self.service["externalreference"].append(reference_entry)
        else:
            self.service["externalreference"] = [reference_entry]

    def set_copyrighttext(self, text):
        self.service["copyrighttext"] = self._text(text)

    def set_comment(self, comment):
        self.service["comment"] = self._text(comment)

    def set_summary(self, summary):
        self.service["summary"] = self._text(summary)

    def set_description(self, description):
        self.service["description"] = self._text(description)

    def set_value(self, key, value):
        self.service[key] = value

    def get_service(self):
        return self.service

    def get_value(self, attribute):
        return self.service.get(attribute, None)

    def debug_service(self):
        print("OUTPUT:", self.service)

    def show_service(self):
        for key in self.service:
            print(f"{key}    : {self.service[key]}")

    def copy_service(self, service_info):
        for key in service_info:
            self.set_value(key, service_info[key])

    def get_name(self):
        return self.get_value("name")

    def _semantic_version(self, version):
        return version.split("-")[0] if "-" in version else version

    def _valid_checksum(self, value):
        # Checksum length is either 32, 40, 64, 96 or 128 characters
        if len(value) not in [32,48,64,96,128]:
            return False
        # Only allow valid hex or decimal digits
        return all(c in string.hexdigits for c in value.lower())
