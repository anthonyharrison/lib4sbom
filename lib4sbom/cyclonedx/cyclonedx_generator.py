# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re
import uuid
from datetime import datetime

from lib4sbom.license import LicenseScanner
from lib4sbom.version import VERSION


class CycloneDXGenerator:
    """
    Generate CycloneDX SBOM.
    """

    CYCLONEDX_VERSION = "1.5"
    DATA_LICENCE = "CC0-1.0"
    PROJECT_ID = "CDXRef-DOCUMENT"
    PACKAGE_PREAMBLE = "CDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        cyclonedx_format="json",
        application="lib4sbom",
        version=VERSION,
    ):
        self.doc = []
        self.package_id = 0
        self.license = LicenseScanner()
        self.format = cyclonedx_format
        self.application = application
        self.application_version = version
        if self.format == "xml":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
        self.relationship = []
        self.sbom_complete = False
        self.include_purl = False
        # Can specify version of CycloneDX through environment variable
        self.cyclonedx_version = os.getenv("LIB4SBOM_CYCLONEDX_VERSION")
        if self.cyclonedx_version is None or self.cyclonedx_version not in ["1.4"]:
            self.cyclonedx_version = self.CYCLONEDX_VERSION

    def store(self, message):
        self.doc.append(message)

    def getBOM(self):
        if not self.sbom_complete:
            if self.format == "xml":
                self.store("</components>")
                # Now process dependencies
                self.store("<dependencies>")
                for element in self.relationship:
                    item = element["ref"]
                    self.store(f'<dependency ref="{item}">')
                    for depends in element["dependsOn"]:
                        self.store(f'<dependency ref="{depends}"/>')
                    self.store("</dependency>")
                self.store("</dependencies>")
                self.store("</bom>")
            else:
                # Add set of detected components to SBOM
                self.doc["components"] = self.component
                self.doc["dependencies"] = self.relationship
            self.sbom_complete = True
        return self.doc

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateDocumentHeader(self, project_name):
        # Assume a new document being created
        self.relationship = []
        self.sbom_complete = False
        if self.format == "xml":
            self.doc = []
            return self.generateXMLDocumentHeader(project_name)
        else:
            self.doc = {}
            self.component = []
            return self.generateJSONDocumentHeader(project_name)

    def generateJSONDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        project_id = self.PROJECT_ID
        if self.cyclonedx_version == self.CYCLONEDX_VERSION:
            # 1.5 version
            self.doc = {
                "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": self.CYCLONEDX_VERSION,
                "serialNumber": urn,
                "version": 1,
                "metadata": {
                    "timestamp": self.generateTime(),
                    "tools": {
                        "components": [
                            {
                                "name": self.application,
                                "version": self.application_version,
                                "type": "application",
                            },
                        ]
                    },
                    "component": {
                        "type": "application",
                        "bom-ref": project_id,
                        "name": project_name,
                    },
                },
            }
        else:
            # Legacy version
            self.doc = {
                "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": self.CYCLONEDX_VERSION,
                "serialNumber": urn,
                "version": 1,
                "metadata": {
                    "timestamp": self.generateTime(),
                    "tools": [
                        {
                            "name": self.application,
                            "version": self.application_version,
                        }
                    ],
                    "component": {
                        "type": "application",
                        "bom-ref": project_id,
                        "name": project_name,
                    },
                },
            }
        return project_id

    def generateXMLDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        project_id = self.PROJECT_ID
        self.store("<?xml version='1.0' encoding='UTF-8'?>")
        self.store("<bom xmlns='http://cyclonedx.org/schema/bom/1.4'")
        self.store(f'serialNumber="{urn}"')
        self.store('version="1">')
        self.store("<metadata>")
        self.store(f"<timestamp>{self.generateTime()}</timestamp>")
        self.store("<tools>")
        self.store(f"<name>{self.application}</name>")
        self.store(f"<version>{self.application_version}</version>")
        self.store("</tools>")
        self.store(f"<component type='application' bom-ref='{project_id}'>")
        self.store(f"<name>{project_name}</name>")
        self.store("</component>")
        self.store("</metadata>")
        self.store("<components>")
        return project_id

    def generateRelationship(self, parent_id, package_id):
        # Check we have valid ids
        if parent_id is None or package_id is None:
            return
        # Avoid self->self relationship
        if parent_id == package_id:
            return
        # Check if entry exists. If so, update list of dependencies
        element_found = False
        for element in self.relationship:
            if element["ref"] == parent_id:
                element_found = True
                # Update list of dependencies if necessary
                if package_id not in element["dependsOn"]:
                    element["dependsOn"].append(package_id)
                    break
        if not element_found:
            # New item found
            dependency = dict()
            dependency["ref"] = parent_id
            dependency["dependsOn"] = [package_id]
            self.relationship.append(dependency)

    def generateComponent(self, id, type, package):
        if self.format == "xml":
            self.generateXMLComponent(id, type, package)
        else:
            self.generateJSONComponent(id, type, package)

    def _process_supplier_info(self, supplier_info):

        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
        )
        # If email found, remove from string
        supplier_name = (
            supplier_info.replace(emails[-1], "") if len(emails) > 0 else supplier_info
        )
        # Get names
        names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+", supplier_name)
        supplier = " ".join(n for n in names)
        email_address = emails[-1] if len(emails) > 0 else ""
        return supplier.strip(), email_address

    def generateJSONComponent(self, id, type, package):
        component = dict()
        if "type" in package:
            component["type"] = package["type"].lower()
        else:
            component["type"] = type.lower()
        component["bom-ref"] = id
        name = package["name"]
        component["name"] = name
        if "version" in package:
            version = package["version"]
            component["version"] = version
        if "supplier" in package:
            # If email address in supplier, separate from name
            supplier_name, supplier_email = self._process_supplier_info(
                package["supplier"]
            )
            # Depends on supplier type
            if package["supplier_type"] != "UNKNOWN":
                # Either a person or orgonisation
                supplier = dict()
                supplier["name"] = supplier_name
                if len(supplier_email) > 0:
                    contact = dict()
                    contact["email"] = supplier_email
                    supplier["contact"] = [contact]
                component["supplier"] = supplier
                if "version" in package:
                    component[
                        "cpe"
                    ] = f'cpe:/a:{supplier_name.replace(" ", "_")}:{name}:{version}'
                # Alternative is it within external reference
        if "description" in package:
            component["description"] = package["description"]
        elif "summary" in package:
            component["description"] = package["summary"]
        if "checksum" in package:
            for checksum in package["checksum"]:
                checksum_entry = dict()
                checksum_entry["alg"] = checksum[0]
                checksum_entry["content"] = checksum[1]
                if "hashes" in component:
                    component["hashes"].append(checksum_entry)
                else:
                    component["hashes"] = [checksum_entry]
        if "licenseconcluded" in package:
            license_id = self.license.find_license(package["licenseconcluded"])
            if license_id not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # A valid SPDX license
                license = dict()
                # SPDX license expression handled separately to single license
                if self.license.license_expression(license_id):
                    license["expression"] = license_id
                else:
                    license["id"] = license_id
                    license_url = self.license.get_license_url(license["id"])
                    if license_url is not None:
                        license["url"] = license_url
                item = dict()
                item["license"] = license
                component["licenses"] = [item]
            elif package["licenseconcluded"] not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # Not a valid SPDX license
                license = dict()
                license["name"] = package["licenseconcluded"]
                item = dict()
                item["license"] = license
                component["licenses"] = [item]
        if "copyrighttext" in package:
            component["copyright"] = package["copyrighttext"]
        if "homepage" in package:
            externalReference = dict()
            externalReference["url"] = package["homepage"]
            externalReference["type"] = "website"
            externalReference["comment"] = "Home page for project"
            component["externalReferences"] = [externalReference]
        if "downloadlocation" in package:
            externalReference = dict()
            externalReference["url"] = package["downloadlocation"]
            externalReference["type"] = "distribution"
            externalReference["comment"] = "Download location for component"
            if "externalReferences" in component:
                component["externalReferences"].append(externalReference)
            else:
                component["externalReferences"] = [externalReference]
        if "externalreference" in package:
            # Potentially multiple entries
            for reference in package["externalreference"]:
                ref_category = reference[0]
                ref_type = reference[1]
                ref_value = reference[2]
                if ref_category == "SECURITY" and ref_type == "cpe23Type":
                    component["cpe"] = ref_value
                if (
                    ref_category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"]
                    and ref_type == "purl"
                ):
                    component["purl"] = ref_value
        if "property" in package:
            for property in package["property"]:
                property_entry = dict()
                property_entry["name"] = property[0]
                property_entry["value"] = property[1]
                if "properties" in component:
                    component["properties"].append(property_entry)
                else:
                    component["properties"] = [property_entry]
        # SPDX items with no corresponding entry are created as properties
        if "licensecomments" in package:
            property_entry = dict()
            property_entry["name"] = "License Comments"
            property_entry["value"] = package["licensecomments"]
            if "properties" in component:
                component["properties"].append(property_entry)
            else:
                component["properties"] = [property_entry]
        if "comments" in package:
            property_entry = dict()
            property_entry["name"] = "Component Comments"
            property_entry["value"] = package["comments"]
            if "properties" in component:
                component["properties"].append(property_entry)
            else:
                component["properties"] = [property_entry]
        self.component.append(component)

    def generateXMLComponent(self, id, type, package):
        self.store(f'<component type="{type}" bom-ref="{id}">')
        name = package["name"]
        version = package["version"]
        self.store(f"<name>{name}</name>")
        self.store(f"<version>{version}</version>")
        if "supplier" in package:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            self.store(
                f'<cpe>cpe:/a:{package["supplier"].replace(" ", "_")}:{name}:{version}</cpe>'
            )
        if "licenseconcluded" in package:
            license_id = self.license.find_license(package["licenseconcluded"])
            # Only include if valid license
            if license_id not in ["UNKNOWN", "NOASSERTION"]:
                self.store("<licenses>")
                self.store("<license>")
                self.store(f'<id>"{license_id}"</id>')
                license_url = self.license.get_license_url(license_id)
                if license_url is not None:
                    self.store(f'<url>"{license_url}"</url>')
                self.store("</license>")
                self.store("</licenses>")
        if "externalreference" in package:
            # Potentially multiple entries
            for reference in package["externalreference"]:
                ref_category = reference[0]
                ref_type = reference[1]
                ref_value = reference[2]
                if ref_category == "SECURITY" and ref_type == "cpe23Type":
                    self.store(f"<cpe>{ref_value}</cpe>")
                if (
                    ref_category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"]
                    and ref_type == "purl"
                ):
                    self.store(f"<purl>{ref_value}</purl>")
        self.store("</component>")
