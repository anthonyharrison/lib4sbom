# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship


class CycloneDXParser:
    def __init__(self):
        pass

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
        cyclonedx_package = SBOMPackage()
        cyclonedx_relationship = SBOMRelationship()
        cyclonedx_document = SBOMDocument()
        # Check valid CycloneDX JSON file (and not SPDX)
        cyclonedx_json_file = data.get("bomFormat", False)
        if cyclonedx_json_file:
            cyclonedx_document.set_version(data["specVersion"])
            cyclonedx_document.set_type("cyclonedx")
            if "metadata" in data:
                if "timestamp" in data["metadata"]:
                    cyclonedx_document.set_created(data["metadata"]["timestamp"])
                if "tools" in data["metadata"]:
                    cyclonedx_document.set_creator(
                        "tool", data["metadata"]["tools"][0]["name"]
                    )
                if "authors" in data["metadata"]:
                    cyclonedx_document.set_creator(
                        "person", data["metadata"]["authors"]["name"]
                    )
                if "component" in data["metadata"]:
                    cyclonedx_document.set_name(data["metadata"]["component"]["name"])
            for d in data["components"]:
                cyclonedx_package.initialise()
                if d["type"] in ["library", "application", "operating-system"]:
                    package = d["name"]
                    cyclonedx_package.set_name(package)
                    version = d["version"]
                    cyclonedx_package.set_version(version)
                    # Record type of component
                    cyclonedx_package.set_type(d["type"])
                    if "supplier" in d:
                        # Assume that this refers to an organisation
                        cyclonedx_package.set_supplier(
                            "Organisation", d["supplier"]["name"]
                        )
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
                    elif "evidence" in d and len(d["evidence"]["licenses"]) > 0:
                        license_data = d["evidence"]["licenses"][0]
                    if license_data is not None:
                        # license_data = d["licenses"][0]
                        if "license" in license_data:
                            if "id" in license_data["license"]:
                                license = license_data["license"]["id"]
                            elif "name" in license_data["license"]:
                                license = license_data["license"]["name"]
                        elif "expression" in license_data:
                            license = license_data["expression"]
                        # Assume License concluded is same as lincense declared
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
                    if package not in packages:
                        # Save package metadata
                        packages[package] = cyclonedx_package.get_package()
            if "dependencies" in data:
                # First relationship is assumed to be the root element
                relationship_type = " DESCRIBES "
                for d in data["dependencies"]:
                    source = d["ref"]
                    for target in d["dependsOn"]:
                        cyclonedx_relationship.initialise()
                        cyclonedx_relationship.set_relationship(
                            source, relationship_type, target
                        )
                        relationships.append(cyclonedx_relationship.get_relationship())
                    relationship_type = " DEPENDS_ON "
        return cyclonedx_document, files, packages, relationships
