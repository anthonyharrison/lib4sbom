# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
import os

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship


class CycloneDXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        self.cyclonedx_package = SBOMPackage()
        self.packages = {}
        self.id = {}
        self.component_id = 0

    def parse(self, sbom_file):
        """parses CycloneDX BOM file extracting package name, version and license"""
        if sbom_file.endswith("json"):
            return self.parse_cyclonedx_json(sbom_file)
        else:
            return {}, {}, {}, []

    def _cyclondex_component(self, d):
        self.cyclonedx_package.initialise()
        self.component_id = self.component_id + 1
        if d["type"] in ["file", "library", "application", "operating-system"]:
            package = d["name"]
            self.cyclonedx_package.set_name(package)
            if "version" in d:
                version = d["version"]
                self.cyclonedx_package.set_version(version)
            else:
                if self.debug:
                    print(f"[ERROR] Version not specified for {package}")
                version = "MISSING"
            # Record type of component
            self.cyclonedx_package.set_type(d["type"])
            # If bom-ref not present, auto generate one
            bom_ref = d.get("bom-ref", f"CycloneDX-Component-{self.component_id}")
            if "supplier" in d:
                # Assume that this refers to an organisation
                supplier_name = d["supplier"]["name"]
                # Check for contact details (email)
                if "contact" in d["supplier"]:
                    for contact in d["supplier"]["contact"]:
                        if "email" in contact:
                            supplier_name = f'{supplier_name} ({contact["email"]})'
                self.cyclonedx_package.set_supplier("Organisation", supplier_name)
            if "author" in d:
                # Assume that this refers to an individual
                self.cyclonedx_package.set_supplier("Person", d["author"])
            if "description" in d:
                self.cyclonedx_package.set_description(d["description"])
            if "hashes" in d:
                # Potentially multiple entries
                for checksum in d["hashes"]:
                    self.cyclonedx_package.set_checksum(
                        checksum["alg"], checksum["content"]
                    )
            license_data = None
            # Multiple ways of defining license data
            if "licenses" in d and len(d["licenses"]) > 0:
                license_data = d["licenses"][0]
            elif "evidence" in d:
                if "licenses" in d["evidence"]:
                    if len(d["evidence"]["licenses"]) > 0:
                        license_data = d["evidence"]["licenses"][0]
            if license_data is not None:
                # Multiple ways of defining licenses
                license = None
                if "license" in license_data:
                    if "id" in license_data["license"]:
                        license = license_data["license"]["id"]
                    elif "name" in license_data["license"]:
                        license = license_data["license"]["name"]
                    elif "expression" in license_data["license"]:
                        license = license_data["license"]["expression"]
                elif "expression" in license_data:
                    license = license_data["expression"]
                if license is not None:
                    # Assume License concluded is same as license declared
                    self.cyclonedx_package.set_licenseconcluded(license)
                    self.cyclonedx_package.set_licensedeclared(license)
            if "copyright" in d:
                self.cyclonedx_package.set_copyrighttext(d["copyright"])
            if "cpe" in d:
                self.cyclonedx_package.set_externalreference(
                    "SECURITY", "cpe23Type", d["cpe"]
                )
            if "purl" in d:
                self.cyclonedx_package.set_externalreference(
                    "PACKAGE-MANAGER", "purl", d["purl"]
                )
            if "properties" in d:
                # Potentially multiple entries
                for property in d["properties"]:
                    self.cyclonedx_package.set_property(
                        property["name"], property["value"]
                    )
            if "externalReferences" in d:
                # Potentially multiple entries
                for reference in d["externalReferences"]:
                    ref_type = reference["type"]
                    ref_url = reference["url"]
                    # Try to map type to package element
                    if ref_type == "website":
                        self.cyclonedx_package.set_homepage(ref_url)
                    elif ref_type == "distribution":
                        self.cyclonedx_package.set_downloadlocation(ref_url)
            # Save package metadata
            self.packages[(package, version)] = self.cyclonedx_package.get_package()
            self.id[bom_ref] = package
            # Handle component assemblies
            if "components" in d:
                for component in d["components"]:
                    self._cyclondex_component(component)

    def parse_cyclonedx_json(self, sbom_file):
        """parses CycloneDX JSON BOM file extracting package name, version and license"""
        data = json.load(open(sbom_file))
        files = {}
        relationships = []
        cyclonedx_relationship = SBOMRelationship()
        cyclonedx_document = SBOMDocument()
        # Check valid CycloneDX JSON file (and not SPDX)
        cyclonedx_json_file = data.get("bomFormat", False)
        if cyclonedx_json_file:
            cyclonedx_version = data["specVersion"]
            cyclonedx_document.set_version(cyclonedx_version)
            cyclonedx_document.set_type("cyclonedx")
            if "metadata" in data:
                if "timestamp" in data["metadata"]:
                    cyclonedx_document.set_created(data["metadata"]["timestamp"])
                if "tools" in data["metadata"]:
                    if cyclonedx_version == "1.5":
                        if "components" in data["metadata"]["tools"]:
                            for component in data["metadata"]["tools"]["components"]:
                                cyclonedx_document.set_creator(
                                    "tool", component["name"]
                                )
                        else:
                            # This is the legacy interface which is deprecated.
                            if self.debug:
                                print("Legacy tool(s) specification still being used.")
                            cyclonedx_document.set_creator(
                                "tool", data["metadata"]["tools"][0]["name"]
                            )
                    else:
                        cyclonedx_document.set_creator(
                            "tool", data["metadata"]["tools"][0]["name"]
                        )

                if "authors" in data["metadata"]:
                    cyclonedx_document.set_creator(
                        "person", data["metadata"]["authors"][0]["name"]
                    )
                if "component" in data["metadata"]:
                    for component_metadata in data["metadata"]["component"]:
                        component_name = component_metadata["name"]
                        cyclonedx_document.set_name(component_name)
                    if "bom-ref" in data["metadata"]["component"]:
                        bom_ref = data["metadata"]["component"]["bom-ref"]
                    else:
                        bom_ref = "CylconeDX-Component-0000"
                    self.id[bom_ref] = component_name
            for d in data["components"]:
                self._cyclondex_component(d)
            if "dependencies" in data:
                # First relationship is assumed to be the root element
                relationship_type = " DESCRIBES "
                for d in data["dependencies"]:
                    source_id = d["ref"]
                    # Get source name
                    source = None
                    if source_id in self.id:
                        source = self.id[source_id]
                    elif self.debug:
                        print(f"[ERROR] Unable to find {source_id}")
                    if source is not None and d.get("dependsOn") is not None:
                        for target_id in d["dependsOn"]:
                            if target_id in self.id:
                                target = self.id[target_id]
                                cyclonedx_relationship.initialise()
                                cyclonedx_relationship.set_relationship(
                                    source, relationship_type, target
                                )
                                cyclonedx_relationship.set_relationship_id(
                                    source_id, target_id
                                )
                                relationships.append(
                                    cyclonedx_relationship.get_relationship()
                                )
                            elif self.debug:
                                print(f"[ERROR] Unable to find {target_id}")
                    relationship_type = " DEPENDS_ON "
        return cyclonedx_document, files, self.packages, relationships
