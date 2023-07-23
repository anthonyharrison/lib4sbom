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

    def parse(self, sbom_file):
        """parses CycloneDX BOM file extracting package name, version and license"""
        if sbom_file.endswith("json"):
            return self.parse_cyclonedx_json(sbom_file)
        else:
            return {}, {}, {}, []

    def parse_cyclonedx_json(self, sbom_file):
        """parses CycloneDX JSON BOM file extracting package name, version and license"""
        data = json.load(open(sbom_file))
        files = {}
        packages = {}
        relationships = []
        id = {}
        cyclonedx_package = SBOMPackage()
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
                        for component in data["metadata"]["tools"]["components"]:
                            cyclonedx_document.set_creator("tool", component["name"])
                    else:
                        cyclonedx_document.set_creator(
                            "tool", data["metadata"]["tools"][0]["name"]
                        )

                if "authors" in data["metadata"]:
                    cyclonedx_document.set_creator(
                        "person", data["metadata"]["authors"][0]["name"]
                    )
                if "component" in data["metadata"]:
                    cyclonedx_document.set_name(data["metadata"]["component"]["name"])
                    id[data["metadata"]["component"]["bom-ref"]] = data["metadata"][
                        "component"
                    ]["name"]
            for d in data["components"]:
                cyclonedx_package.initialise()
                if d["type"] in ["file", "library", "application", "operating-system"]:
                    package = d["name"]
                    cyclonedx_package.set_name(package)
                    if "version" in d:
                        version = d["version"]
                        cyclonedx_package.set_version(version)
                    # Record type of component
                    cyclonedx_package.set_type(d["type"])
                    if "supplier" in d:
                        # Assume that this refers to an organisation
                        supplier_name = d["supplier"]["name"]
                        # Check for contact details (email)
                        if "contact" in d["supplier"]:
                            for contact in d["supplier"]["contact"]:
                                if "email" in contact:
                                    supplier_name = (
                                        f'{supplier_name} ({contact["email"]})'
                                    )
                        cyclonedx_package.set_supplier("Organisation", supplier_name)
                    if "author" in d:
                        # Assume that this refers to an individual
                        cyclonedx_package.set_supplier("Person", d["author"])
                    if "description" in d:
                        cyclonedx_package.set_description(d["description"])
                    if "hashes" in d:
                        # Potentially multiple entries
                        for checksum in d["hashes"]:
                            cyclonedx_package.set_checksum(
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
                            cyclonedx_package.set_licenseconcluded(license)
                            cyclonedx_package.set_licensedeclared(license)
                    if "copyright" in d:
                        cyclonedx_package.set_copyrighttext(d["copyright"])
                    if "cpe" in d:
                        cyclonedx_package.set_externalreference(
                            "SECURITY", "cpe23Type", d["cpe"]
                        )
                    if "purl" in d:
                        cyclonedx_package.set_externalreference(
                            "PACKAGE-MANAGER", "purl", d["purl"]
                        )
                    if "properties" in d:
                        # Potentially multiple entries
                        for property in d["properties"]:
                            cyclonedx_package.set_property(
                                property["name"], property["value"]
                            )
                    if "externalReferences" in d:
                        # Potentially multiple entries
                        for reference in d["externalReferences"]:
                            ref_type = reference["type"]
                            ref_url = reference["url"]
                            # Try to map type to package element
                            if ref_type == "website":
                                cyclonedx_package.set_homepage(ref_url)
                            elif ref_type == "distribution":
                                cyclonedx_package.set_downloadlocation(ref_url)
                    # Save package metadata
                    packages[(package, version)] = cyclonedx_package.get_package()
                    id[d["bom-ref"]] = package
            if "dependencies" in data:
                # First relationship is assumed to be the root element
                relationship_type = " DESCRIBES "
                for d in data["dependencies"]:
                    source_id = d["ref"]
                    # Get source name
                    source = None
                    if source_id in id:
                        source = id[source_id]
                    elif self.debug:
                        print(f"[ERROR] Unable to find {source_id}")
                    if source is not None:
                        for target_id in d["dependsOn"]:
                            if target_id in id:
                                target = id[target_id]
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
        return cyclonedx_document, files, packages, relationships
