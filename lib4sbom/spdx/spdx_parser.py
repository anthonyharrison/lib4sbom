# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json

import yaml
from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.file import SBOMFile
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship


class SPDXParser:
    def __init__(self):
        pass

    def parse(self, sbom_file):
        """parses SPDX SBOM file"""
        if sbom_file.endswith(".spdx"):
            return self.parse_spdx_tag(sbom_file)
        elif sbom_file.endswith(".spdx.json"):
            return self.parse_spdx_json(sbom_file)
        elif sbom_file.endswith((".spdx.yaml", "spdx.yml")):
            return self.parse_spdx_yaml(sbom_file)
        else:
            return {}, {}, {}, []

    def parse_spdx_tag(self, sbom_file):
        """parses SPDX tag value file extracting all SBOM data"""
        DEFAULT_VERSION = ""
        with open(sbom_file) as f:
            lines = f.readlines()
        spdx_document = SBOMDocument()
        packages = {}
        spdx_package = SBOMPackage()
        spdx_package.initialise()
        package = None
        # Maintain mapping of document/file/package ids to names
        elements = {}
        element_name = "UNDEFINED"
        versions = {}
        version = DEFAULT_VERSION
        files = {}
        spdx_file = SBOMFile()
        spdx_file.initialise()
        file = None
        file_element = False
        document_element = False
        spdx_id = "NOT_DEFINED"
        relationships = []
        spdx_relationship = SBOMRelationship()
        spdx_relationship.initialise()
        for line in lines:
            line_elements = line.split(":")
            if line_elements[0] == "SPDXVersion":
                spdx_version = line_elements[1].strip().rstrip("\n")
                spdx_document.set_version(spdx_version)
                spdx_document.set_type("spdx")
                document_element = True
            elif line_elements[0] == "DataLicense":
                license_version = line_elements[1].strip().rstrip("\n")
                spdx_document.set_datalicense(license_version)
            elif line_elements[0] == "LicenseListVersion":
                license_version = line_elements[1].strip().rstrip("\n")
                spdx_document.set_licenselist(license_version)
            elif line_elements[0] == "DocumentName":
                spdx_document_name = line_elements[1].strip().rstrip("\n")
                spdx_document.set_name(spdx_document_name)
                element_name = spdx_document_name
                if not document_element:
                    # ID can come before name
                    elements[spdx_id] = element_name
            elif line_elements[0] == "Created":
                # Capture all data after tag
                created = line[len("Created:") :].strip().rstrip("\n")
                line.find(created)
                spdx_document.set_created(created)
            elif line_elements[0] == "Creator":
                creator_type = line_elements[1]
                # Capture all data after creator type
                creator = (
                    line[line.find(creator_type) + len(creator_type) + 1 :]
                    .strip()
                    .rstrip("\n")
                )
                spdx_document.set_creator(creator_type, creator)
            if line_elements[0] == "FileName":
                # Is this a new file?
                if file is not None and file not in files:
                    # Save file metadata
                    files[file] = spdx_file.get_file()
                file = line_elements[1].strip().rstrip("\n")
                # Reset all variables
                spdx_file.initialise()
                spdx_file.set_name(file)
                file_element = True
                element_name = file
            elif line_elements[0] == "FileType":
                filetype = line_elements[1].strip().rstrip("\n")
                spdx_file.set_filetype(filetype)
            elif line_elements[0] == "SPDXID":
                spdx_id = line_elements[1].strip().rstrip("\n")
                # Applies to either a document, file or package
                if document_element:
                    spdx_document.set_id(spdx_id)
                    document_element = False
                elif file_element:
                    spdx_file.set_id(spdx_id)
                else:
                    spdx_package.set_id(spdx_id)
                # Assume ID is after name
                elements[spdx_id] = element_name
            elif line_elements[0] == "FileChecksum":
                checksum_type = line_elements[1]
                checksum = line_elements[2].strip().rstrip("\n")
                spdx_file.set_checksum(checksum_type, checksum)
            elif line_elements[0] == "LicenseConcluded":
                license_concluded = line_elements[1].strip().rstrip("\n")
                spdx_file.set_licenseconcluded(license_concluded)
            elif line_elements[0] == "LicenseInfoInFile":
                license_info = line_elements[1].strip().rstrip("\n")
                spdx_file.set_licenseinfoinfile(license_info)
            elif line_elements[0] == "LicenseComments":
                license_info = line_elements[1].strip().rstrip("\n")
                spdx_file.set_licensecomment(license_info)
            elif line_elements[0] == "FileCopyrightText":
                copyright_text = line_elements[1].strip().rstrip("\n")
                spdx_file.set_copyrighttext(copyright_text)
            elif line_elements[0] == "FileComment":
                comment_text = line_elements[1].strip().rstrip("\n")
                spdx_file.set_comment(comment_text)
            elif line_elements[0] == "FileNotice":
                note = line_elements[1].strip().rstrip("\n")
                spdx_file.set_notice(note)
            elif line_elements[0] == "FileAttributionText":
                attribution = line_elements[1].strip().rstrip("\n")
                spdx_file.set_attribution(attribution)

            if line_elements[0] == "PackageName":
                # Is this a new package?
                if package is not None:
                    # Save package metadata
                    # if package in packages:
                    #    print (f"Duplicate package detected {package}")
                    # packages[package] = spdx_package.get_package()
                    package_tuple = (package, version)
                    if package_tuple in packages:
                        print(f"Duplicate package detected {package} {version}")
                    packages[package_tuple] = spdx_package.get_package()
                    version = DEFAULT_VERSION
                package = line_elements[1].strip().rstrip("\n")
                # Reset all variables
                spdx_package.initialise()
                spdx_package.set_name(package)
                # Default type of component
                spdx_package.set_type("library")
                file_element = False
                element_name = package
            elif line_elements[0] == "PackageVersion":
                version = line_elements[1].strip().rstrip("\n")
                version = version.split("-")[0]
                version = version.split("+")[0]
                spdx_package.set_version(version)
                # Assume ID is after name
                elements[spdx_id] = element_name
                if package in versions:
                    versions[package].append(version)
                else:
                    versions[package] = [version]
            elif line_elements[0] == "PackageFileName":
                filename = line_elements[1].strip().rstrip("\n")
                spdx_package.set_filename(filename)
            elif line_elements[0] == "PackageSupplier":
                if len(line_elements) == 3:
                    supplier_type = line_elements[1]
                    supplier = line_elements[2].strip().rstrip("\n")
                else:
                    # No type specified
                    supplier_type = "UNKNOWN"
                    supplier = line_elements[1].strip().rstrip("\n")
                spdx_package.set_supplier(supplier_type, supplier)
            elif line_elements[0] == "PackageOriginator":
                originator_type = line_elements[1]
                originator = line_elements[2].strip().rstrip("\n")
                spdx_package.set_originator(originator_type, originator)
            elif line_elements[0] == "PackageDownloadLocation":
                downloadlocation = line[24:].strip().rstrip("\n")
                spdx_package.set_downloadlocation(downloadlocation)
            elif line_elements[0] == "FilesAnalyzed":
                file_analysis = line_elements[1].strip().rstrip("\n")
                spdx_package.set_filesanalysis(file_analysis)
            elif line_elements[0] == "PackageChecksum":
                checksum_type = line_elements[1]
                checksum = line_elements[2].strip().rstrip("\n")
                spdx_package.set_checksum(checksum_type, checksum)
            elif line_elements[0] == "PackageHomePage":
                homepage = line[17:].strip().rstrip("\n")
                spdx_package.set_homepage(homepage)
            elif line_elements[0] == "PackageSourceInfo":
                sourceinfo = line[17:].strip().rstrip("\n")
                spdx_package.set_sourceinfo(sourceinfo)
            elif line_elements[0] == "PackageLicenseConcluded":
                license_concluded = line_elements[1].strip().rstrip("\n")
                spdx_package.set_licenseconcluded(license_concluded)
            elif line_elements[0] == "PackageLicenseDeclared":
                license_declared = line_elements[1].strip().rstrip("\n")
                spdx_package.set_licensedeclared(license_declared)
            elif line_elements[0] == "PackageLicenseComments":
                license_comments = line_elements[1].strip().rstrip("\n")
                spdx_package.set_licensecomments(license_comments)
            elif line_elements[0] == "PackageLicenseInfoFromFiles":
                license_info = line_elements[1].strip().rstrip("\n")
                spdx_package.set_licenseinfoinfiles(license_info)
            elif line_elements[0] == "PackageLicenseCopyrightTest":
                copyright_text = line_elements[1].strip().rstrip("\n")
                spdx_package.set_copyrighttext(copyright_text)
            elif line_elements[0] == "PackageComment":
                comments = line_elements[1].strip().rstrip("\n")
                spdx_package.set_comment(comments)
            elif line_elements[0] == "PackageSummary":
                summary = line_elements[1].strip().rstrip("\n")
                spdx_package.set_summary(summary)
            elif line_elements[0] == "PackageDescription":
                description = line_elements[1].strip().rstrip("\n")
                spdx_package.set_description(description)
            elif line_elements[0] == "ExternalRef":
                # Format is TAG CATEGORY TYPE LOCATOR
                # Need all data after type which may contain ':'
                # Therefore capture all data after Tag
                ext_elements = line.split("ExternalRef:", 1)[1].strip().rstrip("\n")
                ref_category = ext_elements.split()[0]
                ref_type = ext_elements.split()[1]
                ref_locator = ext_elements.split()[2]
                spdx_package.set_externalreference(ref_category, ref_type, ref_locator)
            elif line_elements[0] == "Relationship":
                # Format is TAG SOURCE TYPE TARGET
                relationship_elements = (
                    line.split("Relationship:", 1)[1].strip().rstrip("\n")
                )
                source = relationship_elements.split()[0]
                type = relationship_elements.split()[1]
                target = relationship_elements.split()[2]
                spdx_relationship.initialise()
                spdx_relationship.set_relationship(source, type, target)
                relationships.append(spdx_relationship.get_relationship())
        # Save last package/file
        if file is not None and file not in files:
            # Save file metadata
            files[file] = spdx_file.get_file()
        if package is not None and package not in packages:
            # Save package metadata
            # packages[package] = spdx_package.get_package()
            package_tuple = (package, version)
            packages[package_tuple] = spdx_package.get_package()
        return (
            spdx_document,
            files,
            packages,
            self._transform_relationship(relationships, elements),
        )

    def parse_spdx_json(self, sbom_file):
        """parses SPDX JSON SBOM file extracting SBOM data"""
        data = json.load(open(sbom_file))
        return self._parse_spdx_data(data)

    def _parse_spdx_data(self, data):
        packages = {}
        spdx_package = SBOMPackage()
        files = {}
        spdx_file = SBOMFile()
        relationships = []
        spdx_relationship = SBOMRelationship()
        # Maintain mapping of document/file/package ids to names
        elements = {}
        spdx_document = SBOMDocument()
        # Check valid SPDX JSON file (and not CycloneDX)
        spdx_json_file = data.get("spdxVersion", False)
        if spdx_json_file:
            spdx_document.set_version(data["spdxVersion"])
            spdx_document.set_id(data["SPDXID"])
            spdx_document.set_datalicense(data["dataLicense"])
            if "licenseListVersion" in data:
                spdx_document.set_licenselist(data["licenseListVersion"])
            spdx_document.set_type("spdx")
            spdx_document.set_name(data["name"])
            # Process Creation Info
            spdx_document.set_created(data["creationInfo"]["created"])
            # Potentially multiple entries
            for creator in data["creationInfo"]["creators"]:
                creator_entry = creator.split(":")
                spdx_document.set_creator(creator_entry[0], creator_entry[1])
            elements[data["SPDXID"]] = data["name"]
            if "files" in data:
                for d in data["files"]:
                    spdx_file.initialise()
                    filename = d["fileName"]
                    spdx_file.set_name(filename)
                    elements[d["SPDXID"]] = filename
                    try:
                        if "checksum" in d:
                            # Potentially multiple entries
                            for checksum in d["checksum"]:
                                spdx_file.set_checksum(
                                    checksum["algorithm"], checksum["checkumValue"]
                                )
                        if "licenseConcluded" in d:
                            spdx_file.set_licenseconcluded(d["licenseConcluded"])
                        if "copyrightText" in d:
                            spdx_file.set_copyrighttext(d["copyrightText"])
                        if filename not in files:
                            # Save file metadata
                            files[filename] = spdx_file.get_file()
                    except KeyError as e:
                        print(f"{e} Unable to store file info: {filename}")
            if "packages" in data:
                for d in data["packages"]:
                    spdx_package.initialise()
                    package = d["name"]
                    spdx_package.set_name(package)
                    elements[d["SPDXID"]] = package
                    # Default type of component
                    spdx_package.set_type("library")
                    try:
                        # Version info is not mandatory
                        version = d.get("versionInfo", None)
                        if version is not None:
                            spdx_package.set_version(version)
                        if "supplier" in d:
                            supplier = d["supplier"].split(":")
                            # Type not always specified
                            if len(supplier) == 2:
                                supplier_type = supplier[0]
                                supplier_name = supplier[1].strip().rstrip("\n")
                            else:
                                # No type specified
                                supplier_type = "UNKNOWN"
                                supplier_name = supplier[0].strip().rstrip("\n")
                            spdx_package.set_supplier(supplier_type, supplier_name)
                        if "originator" in d:
                            originator = d["originator"].split(":")
                            spdx_package.set_originator(originator[0], originator[1])
                        if "filesAnaylzed" in d:
                            spdx_package.set_filesAnalyzed(d["filesAnaylzed"])
                        if "filename" in d:
                            spdx_package.set_fileName(d["filename"])
                        if "homepage" in d:
                            spdx_package.set_homepage(d["homepage"])
                        if "checksum" in d:
                            # Potentially multiple entries
                            for checksum in d["checksum"]:
                                spdx_package.set_checksum(
                                    checksum["algorithm"], checksum["checkumValue"]
                                )
                        if "sourceinfo" in d:
                            spdx_package.set_sourceInfo(d["sourceinfo"])
                        if "licenseConcluded" in d:
                            spdx_package.set_licenseconcluded(d["licenseConcluded"])
                        if "licenseDeclared" in d:
                            spdx_package.set_licensedeclared(d["licenseDeclared"])
                        if "licenseComments" in d:
                            spdx_package.set_licensecomments(d["licenseComments"])
                        if "copyrightText" in d:
                            spdx_package.set_copyrighttext(d["copyrightText"])
                        if "downloadLocation" in d:
                            spdx_package.set_downloadlocation(d["downloadLocation"])
                        if "description" in d:
                            spdx_package.set_description(d["description"])
                        if "comment" in d:
                            spdx_package.set_comment(d["comment"])
                        if "summary" in d:
                            spdx_package.set_summary(d["summary"])
                        if "downloadlocation" in d:
                            spdx_package.set_downloadlocation(d["downloadlocation"])
                        if "externalRefs" in d:
                            for ext_ref in d["externalRefs"]:
                                spdx_package.set_externalreference(
                                    ext_ref["referenceCategory"],
                                    ext_ref["referenceType"],
                                    ext_ref["referenceLocator"],
                                )
                        if package not in packages:
                            # Save package metadata
                            packages[package] = spdx_package.get_package()

                    except KeyError as e:
                        print(f"{e} Unable to store package info: {package}")
            if "relationships" in data:
                for d in data["relationships"]:
                    spdx_relationship.initialise()
                    spdx_relationship.set_relationship(
                        d["spdxElementId"],
                        d["relationshipType"],
                        d["relatedSpdxElement"],
                    )
                    relationships.append(spdx_relationship.get_relationship())
        return (
            spdx_document,
            files,
            packages,
            self._transform_relationship(relationships, elements),
        )

    def parse_spdx_yaml(self, sbom_file):
        """parses SPDX YAML SBOM file extracting SBOM data"""
        data = yaml.safe_load(open(sbom_file))
        return self._parse_spdx_data(data)

    def _transform_relationship(self, relationship_list, element_mapping):
        # Translate element ids in each relationship to element name
        spdx_relationship = SBOMRelationship()
        relationships = []
        for rel in relationship_list:
            spdx_relationship.initialise()
            # Only process if relationship source and target have been identified
            if rel["source"] in element_mapping and rel["target"] in element_mapping:
                spdx_relationship.set_relationship(
                    element_mapping[rel["source"]],
                    rel["type"],
                    element_mapping[rel["target"]],
                )
                # Retain ids for look up
                spdx_relationship.set_relationship_id(rel["source"], rel["target"])
                relationships.append(spdx_relationship.get_relationship())
        return relationships
