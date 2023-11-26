# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re
import uuid
from datetime import datetime

from lib4sbom.data.vulnerability import Vulnerability
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
        self.vulnerability = []
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
                if len(self.component) > 0:
                    self.doc["components"] = self.component
                if len(self.relationship) > 0:
                    self.doc["dependencies"] = self.relationship
                if len(self.vulnerability) > 0:
                    self.doc["vulnerabilities"] = self.vulnerability
            self.sbom_complete = True
        return self.doc

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def spec_version(self, version):
        if version in ["1.3", "1.4", "1.5"]:
            self.cyclonedx_version = version

    def generateDocumentHeader(
        self, project_name, component_type, uuid=None, bom_version="1"
    ):
        # Assume a new document being created
        self.relationship = []
        self.sbom_complete = False
        if self.format == "xml":
            self.doc = []
            return self.generateXMLDocumentHeader(project_name, uuid)
        else:
            self.doc = {}
            self.component = []
            return self.generateJSONDocumentHeader(
                project_name, component_type, uuid, bom_version
            )

    def _generate_urn(self):
        return "urn:uuid:" + str(uuid.uuid4())

    def generateJSONDocumentHeader(
        self, project_name, component_type, uuid=None, bom_version="1"
    ):
        if uuid is None:
            urn = self._generate_urn()
        else:
            urn = uuid
        project_id = self.PROJECT_ID
        self.doc = {}
        self.doc[
            "$schema"
        ] = f"http://cyclonedx.org/schema/bom-{self.cyclonedx_version}.schema.json"
        self.doc["bomFormat"] = "CycloneDX"
        self.doc["specVersion"] = self.cyclonedx_version
        self.doc["serialNumber"] = urn
        self.doc["version"] = int(bom_version)
        metadata = {}
        if component_type["timestamp"] is None:
            metadata["timestamp"] = self.generateTime()
        else:
            metadata["timestamp"] = component_type["timestamp"]
        tool = {}
        author = {}
        if component_type["creator"] is not None:
            for creator in component_type["creator"]:
                type, param = creator
                if "#" in param:
                    if type == "tool":
                        tool["name"] = param.split("#")[0]
                        tool["version"] = param.split("#")[1]
                    elif type == "person":
                        author["name"] = param.split("#")[0]
                        author["email"] = param.split("#")[1]
        if len(tool) == 0:
            tool["name"] = self.application
            tool["version"] = self.application_version
        # Tools format changed in version 1.5
        if self.cyclonedx_version == self.CYCLONEDX_VERSION:
            tools = {}
            tool["type"] = "application"
            components = []
            components.append(tool)
            tools["components"] = components
        else:
            tools = []
            tools.append(tool)
        metadata["tools"] = tools
        if len(author) > 0:
            metadata["authors"] = author
        component = {}
        component["type"] = component_type["type"]
        if component_type["supplier"] is not None:
            supplier = {}
            supplier["name"] = component_type["supplier"]
            component["supplier"] = supplier
        if component_type["version"] is not None:
            component["version"] = component_type["version"]
        if component_type["bom-ref"] is not None:
            component["bom-ref"] = component_type["bom-ref"]
        else:
            component["bom-ref"] = project_id
        component["name"] = project_name
        metadata["component"] = component
        self.doc["metadata"] = metadata
        return component["bom-ref"]

    def generateXMLDocumentHeader(self, project_name, uuid=None):
        if uuid is None:
            urn = self._generate_urn()
        else:
            urn = uuid
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
        names = re.findall(r"[a-zA-Z0-9\.\-]+[ A-Za-z0-9]*", supplier_name)
        supplier = " ".join(n for n in names)
        email_address = emails[-1] if len(emails) > 0 else ""
        return supplier.strip(), email_address

    def generateJSONComponent(self, id, type, package):
        component = dict()
        if "type" in package:
            component["type"] = package["type"].lower()
        else:
            component["type"] = type.lower()
        if package.get("bom-ref") is None:
            component["bom-ref"] = id
        else:
            component["bom-ref"] = package.get("bom-ref")
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
                # Either a person or organisation
                supplier = dict()
                supplier["name"] = supplier_name
                if len(supplier_email) > 0:
                    contact = dict()
                    contact["email"] = supplier_email
                    supplier["contact"] = [contact]
                component["supplier"] = supplier
                if "version" in package:
                    if component["type"] == "operating-system":
                        cpe_type = "/o"
                    else:
                        cpe_type = "/a"
                    component[
                        "cpe"
                    ] = f'cpe:{cpe_type}:{supplier_name.replace(" ", "_")}:{name}:{version}'
                # Alternative is it within external reference
        if "originator" in package:
            component["author"] = package["originator"]
        if "description" in package:
            component["description"] = package["description"]
        elif "summary" in package:
            component["description"] = package["summary"]
        if "checksum" in package:
            for checksum in package["checksum"]:
                checksum_entry = dict()
                checksum_entry["alg"] = checksum[0].replace("SHA", "SHA-")
                checksum_entry["content"] = checksum[1]
                if "hashes" in component:
                    component["hashes"].append(checksum_entry)
                else:
                    component["hashes"] = [checksum_entry]
        if "licenseconcluded" in package or "licensedeclared" in package:
            if "licenseconcluded" in package:
                license_definition = package["licenseconcluded"]
            else:
                license_definition = package["licensedeclared"]
            license_id = self.license.find_license(license_definition)
            if license_id not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # A valid SPDX license
                license = dict()
                # SPDX license expression handled separately to single license
                if self.license.license_expression(license_id):
                    license["expression"] = license_id
                    component["licenses"] = [license]
                else:
                    license["id"] = license_id
                    license_url = self.license.get_license_url(license["id"])
                    if license_url is not None:
                        license["url"] = license_url
                    item = dict()
                    item["license"] = license
                    component["licenses"] = [item]
            elif license_definition not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # Not a valid SPDX license
                license = dict()
                if "licensename" in package:
                    license["name"] = package["licensename"]
                    text = {}
                    text["content"] = license_definition
                    license["text"] = text
                else:
                    license["name"] = license_definition
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
                elif (
                    ref_category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"]
                    and ref_type == "purl"
                ):
                    component["purl"] = ref_value
                else:
                    externalReference = dict()
                    externalReference["url"] = ref_value
                    externalReference["type"] = ref_type
                    externalReference["comment"] = ref_category
                    if "externalReferences" in component:
                        component["externalReferences"].append(externalReference)
                    else:
                        component["externalReferences"] = [externalReference]
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
        if "comment" in package:
            property_entry = dict()
            property_entry["name"] = "Comment"
            property_entry["value"] = package["comment"]
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

    def generate_vulnerability_data(self, vulnerabilities):
        statements = []
        for vuln in vulnerabilities:
            vulnerability = {}
            vuln_info = Vulnerability(validation="cyclonedx")
            vuln_info.copy_vulnerability(vuln)
            vulnerability["bom-ref"] = vuln_info.get_value("bom-ref")
            vulnerability["id"] = vuln_info.get_value("id")
            if vulnerability["id"].startswith("CVE-"):
                # NVD Data source
                source = {}
                source["name"] = "NVD"
                source[
                    "url"
                ] = f"https://nvd.nist.gov/vuln/detail/{vulnerability['id']}"
                vulnerability["source"] = source
            if "description" in vuln:
                vulnerability["description"] = vuln_info.get_value("description")
            vulnerability["updated"] = self.doc["metadata"]["timestamp"]
            if "created" in vuln:
                vulnerability["created"] = vuln_info.get_value("created")
            else:
                vulnerability["created"] = vulnerability["updated"]
            analysis = {}
            analysis["state"] = vuln_info.get_value("status")
            if analysis["state"] is None or not vuln_info.validate_status(
                analysis["state"]
            ):
                analysis["state"] = "in_triage"
            if "comment" in vuln:
                analysis["detail"] = vuln_info.get_value("comment")
            if "justification" in vuln:
                analysis["justification"] = vuln_info.get_value("justification")
            vulnerability["analysis"] = analysis
            affects = []
            affected = {}
            affected["ref"] = vulnerability["bom-ref"]
            version_info = {}
            version_info["version"] = vuln_info.get_value("release")
            if analysis["state"] == "not_affected":
                version_info["status"] = "unaffected"
            elif analysis["state"] == "in_triage":
                version_info["status"] = "unknown"
            else:
                version_info["status"] = "affected"
            affected["version"] = version_info
            affects.append(affected)
            vulnerability["affects"] = affects
            statements.append(vulnerability)
        self.vulnerability = statements
