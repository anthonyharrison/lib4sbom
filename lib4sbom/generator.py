# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import semantic_version

from lib4sbom.cyclonedx.cyclonedx_generator import CycloneDXGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOMData
from lib4sbom.spdx.spdx_generator import SPDXGenerator
from lib4sbom.version import VERSION


class SBOMGenerator:
    """
    Simple SBOM Generator.
    """

    def __init__(
        self,
        validate_license: bool = True,
        sbom_type: str = "spdx",
        format: str = "tag",
        application: str = "lib4sbom",
        version: str = VERSION,
    ):

        self.format = format.lower()
        self.sbom_type = sbom_type.lower()
        # Ensure specified format is supported
        if self.format not in ["tag", "json", "xml", "yaml"]:
            # Set a default format
            self.format = "json"
        if self.sbom_type not in ["spdx", "cyclonedx"]:
            # Set a default SBOM type
            self.sbom_type = "spdx"
        # Ensure format is compatible with SBOM type
        if self.sbom_type == "spdx":
            # XML not valid for SPDX
            if self.format == "xml":
                self.format = "tag"
        else:
            # Tag and YAML not valid for CycloneDX
            if self.format in ["tag", "yaml"]:
                self.format = "json"

        if self.sbom_type == "spdx":
            self.bom = SPDXGenerator(
                validate_license, self.format, application, version
            )
        else:
            self.bom = CycloneDXGenerator(self.format, application, version)
        self.sbom_complete = False
        self.element_set = {}
        self.sbom = None

    def get_format(self) -> str:
        return self.format

    def get_type(self) -> str:
        return self.sbom_type

    def get_sbom(self):
        return self.sbom

    def generate(
        self,
        project_name: str,
        sbom_data: SBOMData,
        filename: str = "",
        send_to_output: bool = True,
    ) -> None:
        if len(sbom_data) > 0:
            self.element_set = {}
            if project_name == "":
                print("[ERROR] Project name missing")
                project_name = "Default_project"
            if self.sbom_type == "spdx":
                self._generate_spdx(project_name, sbom_data)
                self.sbom = self._get_spdx()
            else:
                self._generate_cyclonedx(project_name, sbom_data)
                self.sbom = self._get_cyclonedx()
            if send_to_output:
                sbom_out = SBOMOutput(filename, output_format=self.format)
                sbom_out.generate_output(self.sbom)

    def _generate_spdx(self, project_name: str, sbom_data: SBOMData) -> None:
        self.sbom_complete = False
        if "document" in sbom_data and "name" in sbom_data["document"]:
            # Use existing document name
            project_id = self.bom.generateDocumentHeader(sbom_data["document"]["name"])
            self._save_element(sbom_data["document"]["name"], project_id)
        else:
            project_id = self.bom.generateDocumentHeader(project_name)
            self._save_element(project_name, project_id)
        if "files" in sbom_data:
            # Process list of files
            if len(sbom_data["files"]) is not None:
                sbom_files = [x for x in sbom_data["files"].values()]
                id = 1
                relationship = "CONTAINS"
                for file in sbom_files:
                    self.bom.generateFileDetails(
                        file["name"],
                        str(id) + "-" + file["name"].replace("/", "-"),
                        file,
                        project_id,
                        relationship,
                    )
                    self._save_element(
                        file["name"], str(id) + "-" + file["name"].replace("/", "-")
                    )
                    id = id + 1
        # Process list of packages
        if "packages" in sbom_data:
            id = 1
            sbom_packages = [x for x in sbom_data["packages"].values()]
            for package in sbom_packages:
                if "name" not in package:
                    print(f"[ERROR] Name missing in {package}")
                    continue
                product = package["name"]
                my_id = package.get("id", None)
                parent = "-"
                # if product not in self.element_set:
                self._save_element(product, str(id) + "-" + product, my_id)
                if parent == "-":
                    parent_id = project_id
                    relationship = "DESCRIBES"
                else:
                    if parent in self.element_set:
                        parent_id = self._get_element(parent)
                        relationship = "DEPENDS_ON"
                self.bom.generatePackageDetails(
                    product,
                    str(id) + "-" + product,
                    package,
                    parent_id,
                    relationship,
                )
                id = id + 1
                # else:
                if parent == "-":
                    parent_id = project_id
                    relationship = "DESCRIBES"
                elif parent in self.element_set:
                    relationship = "DEPENDS_ON"
                    parent_id = self._get_element(parent)
                else:
                    parent_id = None
                if parent_id is not None:
                    self.bom.generateRelationship(
                        self.bom.package_ident(parent_id),
                        self.bom.package_ident(self._get_element(product)),
                        relationship,
                    )
        if "relationships" in sbom_data:
            for relationship in sbom_data["relationships"]:
                if (
                    relationship["source"] in self.element_set
                    and relationship["target"] in self.element_set
                ):
                    self.bom.generateRelationship(
                        self.bom.package_ident(
                            self._get_element(
                                relationship["source"], relationship["source_id"]
                            )
                        ),
                        self.bom.package_ident(
                            self._get_element(
                                relationship["target"], relationship["target_id"]
                            )
                        ),
                        " " + relationship["type"] + " ",
                    )
                else:
                    print(
                        "[ERROR] Relationship not copied between",
                        relationship["source"],
                        " and ",
                        relationship["target"],
                    )

    def _get_spdx(self):
        if not self.sbom_complete:
            self.bom.showRelationship()
            self.sbom_complete = True
        return self.bom.getBOM()

    def _get_relationships(self):
        return self.bom.getRelationships()

    def _get_cyclonedx(self):
        return self.bom.getBOM()

    def _save_element(self, name, id, id2=None):
        if name not in self.element_set:
            self.element_set[name] = [(id, id2)]
        else:
            # Duplicated name
            self.element_set[name].append((id, id2))

    def _semantic_version(self, version):
        # Semantic version requires at least major.minor.patch.
        # Add any component parts which are missing
        if version.count(".") > 1:
            version_spec = version
        elif version.count(".") == 1:
            version_spec = version + ".0"
        else:
            version_spec = version + ".0.0"
        return semantic_version.Version(version_spec)

    def _get_element(self, name, id=None):
        check = self.element_set.get(name)
        if check is not None:
            if len(check) > 1:
                # Duplicate name identified. Match against id
                # If no version specified, select component with the latest
                # version based on semantic version ordering
                # Each element entry is <package id> <version id of form name_version>
                if id is None:
                    latest_version = self._semantic_version(check[0][1].split("_")[-1])
                index = i = 0
                for c in check:
                    if id is None:
                        current_version = self._semantic_version(c[1].split("_")[-1])
                        if current_version > latest_version:
                            latest_version = current_version
                            index = i
                    elif c[1] == id:
                        return c[0]
                    i += 1
                return check[index][0]
            else:
                return check[0][0]
        return check

    def _generate_cyclonedx(self, project_name: str, sbom_data: SBOMData) -> None:
        if "document" in sbom_data and "name" in sbom_data["document"]:
            # Use existing document name
            project_id = self.bom.generateDocumentHeader(sbom_data["document"]["name"])
            self._save_element(sbom_data["document"]["name"], project_id)
        else:
            project_id = self.bom.generateDocumentHeader(project_name)
            self._save_element(project_name, project_id)
        parent = project_name
        # Process list of files
        if "files" in sbom_data:
            # Process list of files
            if len(sbom_data["files"]) is not None:
                sbom_files = [x for x in sbom_data["files"].values()]
                id = 1
                for file in sbom_files:
                    self.bom.generateComponent(file["name"], "file", file)
                    self.bom.generateRelationship(project_id, file["name"])
                    self._save_element(file["name"], file["name"])
                    id = id + 1
        # Process list of packages
        if "packages" in sbom_data:
            id = 1
            sbom_packages = [x for x in sbom_data["packages"].values()]
            for package in sbom_packages:
                product = package["name"]
                my_id = package.get("id", None)
                self._save_element(product, str(id) + "-" + product, my_id)
                if parent == "-":
                    type = "application"
                else:
                    type = "library"
                self.bom.generateComponent(
                    self._get_element(product, my_id), type, package
                )
                # if parent != "-":
                self.bom.generateRelationship(
                    self._get_element(parent), self._get_element(product, my_id)
                )
                id = id + 1
        if "relationships" in sbom_data:
            for relationship in sbom_data["relationships"]:
                self.bom.generateRelationship(
                    self._get_element(
                        relationship["source"], relationship["source_id"]
                    ),
                    self._get_element(
                        relationship["target"], relationship["target_id"]
                    ),
                )
