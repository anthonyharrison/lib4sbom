# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re
import uuid
from datetime import datetime

from lib4sbom.data.identifier import SBOMIdentifier
from lib4sbom.license import LicenseScanner
from lib4sbom.version import VERSION


class SPDX3Generator:
    """
    Generate SPDX JSON-LD SBOM.
    """

    SPDX_VERSION = "3.0.1"
    DATA_LICENSE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_PREAMBLE = f"{SPDX_NAMESPACE}SPDXRef-"
    SPDX_PROJECT_ID = f"{SPDX_PREAMBLE}DOCUMENT"
    PACKAGE_PREAMBLE = f"{SPDX_PREAMBLE}Package-"
    FILE_PREAMBLE = f"{SPDX_PREAMBLE}File-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        validate_license: True,
        spdx_format="jsonld",
        application="lib4sbom",
        version=VERSION,
    ):
        self.package_id = 0
        self.validate_license = validate_license
        self.license = LicenseScanner()
        self.relationship = []
        self.format = spdx_format
        self.application = application
        self.application_version = version
        self.doc = {}
        self.component = []
        self.file_component = []
        self.relationships = []
        self.licenses = []
        self.include_purl = False
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        self.organisation = None
        self.tool = None
        self.spdx_version = self.SPDX_VERSION
        self.license_info = []
        self.license_id = 1

    def getBOM(self):
        return self.doc

    def getRelationships(self):
        return self.relationship

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _uuid(self, id=None):
        if id is None:
            return str(uuid.uuid4())
        return id

    def _creatorcomment(self, lifecycle=None):
        lifecycle_to_sbomtype = {
            "design": "Design",
            "pre-build": "Source",
            "build": "Build",
            "post-build": "Analyzed",
            "operations": "Deployed",
            "discovery": "Runtime",
        }
        default_text = "This document has been automatically generated."
        if lifecycle is not None:
            # Might not be using CISA SBOM types
            if lifecycle_to_sbomtype.get(lifecycle.lower()) is not None:
                return f"SBOM Type: {lifecycle_to_sbomtype[lifecycle]} - {default_text}"
            if lifecycle.lower() in [
                "design",
                "source",
                "build",
                "analyzed",
                "deployed",
                "runtime",
            ]:
                return f"SBOM Type: {lifecycle.capitalize()} - {default_text}"
        return default_text

    # SPDX3 Helper classes

    def create_doc(self):
        self.doc["@context"] = (
            f"https://spdx.org/rdf/{self.SPDX_VERSION}/spdx-context.jsonld"
        )
        self.doc["@graph"] = []
        self.creationid = 0
        self.id = 1
        self.document_generation_time = self.generateTime()
        self.license_list_id = self.license.get_license_version()

    def creation_info(self):
        creation = {}
        creation["type"] = "CreationInfo"
        creation["@id"] = f"_:creationinfo{self.creationid}"
        creation["created"] = self.document_generation_time
        # Meeds to reference organisation element
        if self.organisation is not None:
            creation["createdBy"] = [self.organisation]
        else:
            # Need to create an agent
            creation["createdBy"] = [
                self.create_type("SoftwareAgent", {"name": self.application})
            ]
        # Needs to reference tool element
        if self.tool is not None:
            creation["createdUsing"] = [self.tool]
        creation["specVersion"] = self.SPDX_VERSION
        creation["comment"] = "This document has been automatically generated."
        # creation["creationInfo"] = f"_:creationinfo{self.creationid}"
        # creation["spdxId"] = f"{self.SPDX_PREAMBLE}CreationInfo-{self.id}"
        self.doc["@graph"].append(creation)
        # self.creationid = self.creationid + 1

    def create_document(self, bom_id, project_name):
        # Create data licence
        data_licence_id = self.create_type(
            "simplelicensing_LicenseExpression",
            {"simplelicensing_licenseExpression": self.DATA_LICENSE},
        )
        document_properties = {
            "name": project_name,
            "dataLicense": data_licence_id,
            "rootElement": [bom_id],
            "profileConformance": ["core", "software", "security", "simpleLicensing"],
        }
        self.create_type("SpdxDocument", document_properties)

    def create_type(self, element_type, element_info):
        if len(element_info) > 0:
            # Need to reference a creation item
            type_element = {}
            type_element["type"] = element_type
            if element_info.get("spdxId") is None:
                element_id = (
                    f"{self.SPDX_PREAMBLE}{element_type.split('_')[-1]}-{self.id}"
                )
                type_element["spdxId"] = element_id
            else:
                element_id = element_info.get("spdxId")
            type_element["creationInfo"] = f"_:creationinfo{self.creationid}"
            for key, value in element_info.items():
                type_element[key] = value
            self.doc["@graph"].append(type_element)
            self.id = self.id + 1
            return element_id
        return None

    def create_package(self, component_details):
        # Map spdx2 attributes to SPDX3 attributes
        package_attributes = {
            "downloadLocation": "software_downloadLocation",
            "homepage": "software_homePage",
            "url": "packageURL",
            "name": "name",
            "versionInfo": "software_packageVersion",
            "sourceInfo": "sourceInfo",
            "builtDate": "builtTime",
            "primaryPackagePurpose": "software_primaryPurpose",
            "description": "description",
            "summary": "summary",
            "comment": "comment",
            "SPDXID": "spdxId",
            "copyrightText": "software_copyrightText",
        }
        package_details = {}
        # map licence attributes to SPDX3 relationships
        license_attributes = {
            "licenseConcluded": "hasConcludedLicense",
            "licenseDeclared": "hasDeclaredLicense",
        }
        license_details = {}
        external_details = []
        for key, value in component_details.items():
            if key in package_attributes.keys():
                package_details[package_attributes[key]] = value
        # convert primary purpose to SPDX3
        if package_details.get("software_primaryPurpose") is not None:
            package_details["software_primaryPurpose"] = package_details[
                "software_primaryPurpose"
            ].lower()
        if "supplier" in component_details:
            supplier = component_details["supplier"].split(":")
            # Extract details of the supplier. Assume format is name (email address)
            pattern = r"^(.*?)(?:\s*\((.*?)\))?\s*$"
            if len(supplier) > 1:
                match = re.search(pattern, supplier[1])
                if match:
                    name = match.group(1).strip()
                    email = match.group(2)
                    supplier_info = {"name": name}
                    if email is not None:
                        ext_id = {
                            "type": "ExternalIdentifier",
                            "identifier": email.strip(),
                            "externalIdentifierType": "email",
                        }
                        supplier_info["externalIdentifier"] = [ext_id]
                    supplier_id = self.create_type(supplier[0].capitalize(), supplier_info)
            else:
                # NOASSERTION
                supplier_id = self.create_type("Agent", {"name": supplier[0]})
            package_details["suppliedBy"] = supplier_id
        if "checksums" in component_details:
            for checksum in component_details["checksums"]:
                checksum_entry = dict()
                checksum_entry["type"] = "Hash"
                checksum_entry["algorithm"] = checksum["algorithm"].lower()
                checksum_entry["hashValue"] = checksum["checksumValue"]
                if "verifiedUsing" in package_details:
                    package_details["verifiedUsing"].append(checksum_entry)
                else:
                    package_details["verifiedUsing"] = [checksum_entry]
        if "externalRefs" in component_details:
            for ref in component_details["externalRefs"]:
                external_element = {}
                external_element["type"] = "ExternalIdentifier"
                # translate from SPDX2 types to SPDX3 types
                convert_type = {
                    "cpe22type": "cpe22",
                    "cpe23type": "cpe23",
                    "purl": "packageUrl",
                }
                # if PURL prefer to use dedicated attribute
                if ref["referenceType"].lower() == "purl":
                    package_details["software_packageUrl"] = ref["referenceLocator"]
                else:
                    if convert_type.get(ref["referenceType"].lower()) is not None:
                        external_element["externalIdentifierType"] = convert_type.get(
                            ref["referenceType"].lower()
                        )
                    else:
                        external_element["externalIdentifierType"] = "other"
                    external_element["identifier"] = ref["referenceLocator"]
                    external_details.append(external_element)
        if len(external_details) > 0:
            package_details["externalIdentifier"] = external_details
        for key, _ in license_attributes.items():
            if key in component_details.keys():
                license_details = {}
                license_details["relationshipType"] = license_attributes[key]
                licence_id = self.license.find_license_id(component_details[key])
                licence_url = self.license.get_license_url(licence_id)
                if licence_url is not None:
                    # create a license object and reference it
                    licence_ref = self.create_type(
                        "simplelicensing_LicenseExpression",
                        {
                            "simplelicensing_licenseExpression": component_details[key],
                            "simplelicensing_licenseListVersion": self.license_list_id,
                        },
                    )
                    license_details["to"] = [licence_ref]
                else:
                    license_details["to"] = [
                        "https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense"
                    ]
                license_details["from"] = package_details.get("spdxId")
                self.create_type("Relationship", license_details)
        package_id = self.create_type("software_Package", package_details)
        if self.bom_id is None:
            self.bom_id = self.create_type(
                "software_Sbom",
                {
                    "name": self.project_name,
                    "rootElement": [package_id],
                    "software_sbomType": [self.lifecycle],
                },
            )
            self.create_document(self.bom_id, self.project_name)

    def create_file(self, file_details):
        self.create_type("software_File", file_details)

    def create_relationship(self, relationship_details):
        relationship_info = {}
        relationship_info["from"] = relationship_details["spdxElementId"]
        relationship_info["relationshipType"] = (
            relationship_details["relationshipType"]
            .lower()
            .replace("depends_on", "dependsOn")
        )
        relationship_info["to"] = [relationship_details["relatedSpdxElement"]]
        relationship_info["completeness"] = "noAssertion"
        self.create_type("Relationship", relationship_info)

    def generateDocumentHeader(
        self, project_name, uuid=None, lifecycle=None, organisation=None
    ):
        if organisation is not None:
            self.organisation = organisation
            if len(self.organisation) == 0:
                self.organisation = None
        # Assume a new document being created
        self.doc = {}
        self.component = []
        self.file_component = []
        self.relationships = []
        self.create_doc()
        self.tool = self.create_type(
            "Tool", {"name": f"{self.application}-{self.application_version}"}
        )
        self.creation_info()
        if self.organisation is not None:
            self.organisation = self.create_type(
                "Organization", {"name": self.organisation}
            )
        self.bom_id = None
        self.lifecycle = lifecycle if lifecycle is not None else "build"
        self.project_name = project_name
        # Default value will be updated when SBOM element created
        return self.SPDX_PROJECT_ID

    def _validate_spdxid(self, id, preamble):
        spdx_id = ""
        # SPDX id can only contain letters, numbers, ., and/or -.
        for i in str(id):
            if i.isalnum():
                spdx_id = spdx_id + i
            elif i in [".", "-"]:
                spdx_id = spdx_id + i
            else:
                # Invalid characters are replaced
                spdx_id = spdx_id + "-"
        # Check preamble not present
        if spdx_id.startswith(preamble):
            return spdx_id
        return preamble + spdx_id

    def package_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self._validate_spdxid(id, self.SPDX_PREAMBLE)
        return str(id)

    def file_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self._validate_spdxid(id, self.FILE_PREAMBLE)
        return str(id)

    def license_ref(self):
        return f"LicenseRef-{self.license_id}"

    def license_ident(self, license):
        if len(license) == 0:
            return "NOASSERTION"
        elif self.validate_license:
            if license != "UNKNOWN":
                derived_license = self.license.find_license(license)
                if derived_license not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                    return derived_license
                # Not an SPDX License id
            return "NOASSERTION"
        else:
            # No validation
            return license

    def _text(file, text_item):
        if text_item not in ["NONE", "NOASSERTION"]:
            if len(text_item) > 0:
                return f"<text>{text_item}</text>"
        return text_item

    def _file_name(self, name):
        # ensure name is a relative filename
        if name.startswith("/"):
            return name
        elif name.startswith("./"):
            return name
        else:
            return "./" + name

    def generateJSONPackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        component = dict()
        package_id = self.package_ident(id)
        component["SPDXID"] = package_id
        component["name"] = package
        if "version" in package_info:
            version = package_info["version"]
            component["versionInfo"] = version
        elif self.debug:
            print(f"[WARNING] **** version missing for {package}")
        if "type" in package_info:
            component["primaryPackagePurpose"] = (
                package_info["type"].upper().replace("-", "_")
            )
        else:
            component["primaryPackagePurpose"] = "LIBRARY"
        if "supplier" in package_info:
            if package_info["supplier_type"] != "UNKNOWN":
                component["supplier"] = (
                    package_info["supplier_type"] + ": " + package_info["supplier"]
                )
            else:
                component["supplier"] = "NOASSERTION"
        if "originator" in package_info:
            if package_info["originator_type"] != "UNKNOWN":
                component["originator"] = (
                    package_info["originator_type"] + ": " + package_info["originator"]
                )
            else:
                component["originator"] = "NOASSERTION"
        component["downloadLocation"] = package_info.get(
            "downloadlocation", "NOASSERTION"
        )
        files_analysed = package_info.get("filesanalysis", False)
        component["filesAnalyzed"] = files_analysed
        if "filename" in package_info:
            component["packageFileName"] = package_info["filename"]
        if "evidence" in package_info:
            for evidence in package_info["evidence"]:
                component["packageFileName"] = evidence
        if "homepage" in package_info:
            component["homepage"] = package_info["homepage"]
        if "checksum" in package_info:
            # Potentially multiple entries
            for checksum in package_info["checksum"]:
                checksum_entry = dict()
                checksum_entry["algorithm"] = checksum[0]
                checksum_entry["checksumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "sourceinfo" in package_info:
            component["sourceInfo"] = package_info["sourceinfo"]
        if "licenseconcluded" in package_info:
            if "licensename" in package_info:
                # User defined license
                component["licenseConcluded"] = self.license_ref()
                self.license_info.append(
                    {
                        "id": self.license_ref(),
                        "name": package_info["licensename"],
                        "text": package_info.get("licensetext", ""),
                    }
                )
                self.license_id = self.license_id + 1
            else:
                component["licenseConcluded"] = self.license_ident(
                    package_info["licenseconcluded"]
                )
        if "licensedeclared" in package_info:
            if "licensename" in package_info:
                # User defined license
                component["licenseDeclared"] = self.license_ref()
                self.license_info.append(
                    {
                        "id": self.license_ref(),
                        "name": package_info["licensename"],
                        "text": package_info.get("licensetext", ""),
                    }
                )
                self.license_id = self.license_id + 1
            else:
                component["licenseDeclared"] = self.license_ident(
                    package_info["licensedeclared"]
                )
        if "licenselist" in package_info:
            # Handle multiple licenses from a CycloneDX SBOM
            license_expression = ""
            for license in package_info["licenselist"]:
                if "id" in license:
                    license_expression = license_expression + license["id"] + " AND "
            # Remove extraneous " AND "
            license_expression = license_expression[:-4]
            component["licenseDeclared"] = license_expression
            component["licenseConcluded"] = license_expression
        if "licensecomments" in package_info:
            component["licenseComments"] = package_info["licensecomments"]
        if files_analysed:
            # Only if files have been analysed
            if "licenseinfoinfiles" in package_info:
                for info in package_info["licenseinfoinfile"]:
                    if "licenseInfoInFiles" in component:
                        component["licenseInfoInFiles"].append(self.license_ident(info))
                    else:
                        component["licenseInfoInFiles"] = [self.license_ident(info)]
        component["copyrightText"] = package_info.get("copyrighttext", "NOASSERTION")
        if "description" in package_info:
            component["description"] = package_info["description"]
        if "comment" in package_info:
            component["comment"] = package_info["comment"]
        if "summary" in package_info:
            component["summary"] = package_info["summary"]
        if "attribution" in package_info:
            # Potentially multiple entries
            for attribution in package_info["attribution"]:
                attribution_data = dict()
                # Unclear what field should be from SPDX specification
                attribution_data["value"] = attribution
                if "attribution" in component:
                    component["attribution"].append(attribution_data)
                else:
                    component["attribution"] = [attribution_data]
        if "release_date" in package_info:
            if (
                package_info["release_date"] is not None
                and len(package_info["release_date"]) > 0
            ):
                component["releaseDate"] = package_info["release_date"]
        if "build_date" in package_info:
            if len(package_info["build_date"]) > 0:
                component["builtDate"] = package_info["build_date"]
        if "externalreference" in package_info:
            # Potentially multiple entries
            for reference in package_info["externalreference"]:
                if reference[0] in [
                    "SECURITY",
                    "PACKAGE-MANAGER",
                    "PACKAGE_MANAGER",
                    "OTHER",
                ]:
                    ref_value = reference[2]
                    if reference[1] == "purl":
                        # Validate purl
                        purl_validator = SBOMIdentifier(ref_value)
                        if not purl_validator.validate():
                            # correct PURL value
                            ref_value = purl_validator.fix()
                    reference_data = dict()
                    reference_data["referenceCategory"] = reference[0].replace("_", "-")
                    reference_data["referenceType"] = reference[1]
                    reference_data["referenceLocator"] = ref_value
                    if "externalRefs" in component:
                        component["externalRefs"].append(reference_data)
                    else:
                        component["externalRefs"] = [reference_data]
        self.create_package(component)

    def generateJSONFileDetails(self, file, id, file_info, parent_id, relationship):
        component = dict()
        file_id = self.file_ident(id)
        component["SPDXID"] = file_id
        component["fileName"] = self._file_name(file)
        if "copyrighttext" in file_info:
            component["copyrightText"] = file_info["copyrighttext"]
        if "licenseconcluded" in file_info:
            component["licenseConcluded"] = self.license_ident(
                file_info["licenseconcluded"]
            )
        if "filetype" in file_info:
            for type in file_info["filetype"]:
                if "fileTypes" in component:
                    component["fileTypes"].append(type)
                else:
                    component["fileTypes"] = [type]
        if "licenseinfoinfile" in file_info:
            for info in file_info["licenseinfoinfile"]:
                if "licenseInfoInFiles" in component:
                    component["licenseInfoInFiles"].append(self.license_ident(info))
                else:
                    component["licenseInfoInFiles"] = [self.license_ident(info)]
        if "licensecomment" in file_info:
            component["licenseComments"] = file_info["licensecomment"]
        if "checksum" in file_info:
            # Potentially multiple entries
            for checksum in file_info["checksum"]:
                checksum_entry = dict()
                checksum_entry["algorithm"] = checksum[0]
                checksum_entry["checksumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "comment" in file_info:
            component["comment"] = file_info["comment"]
        if "notice" in file_info:
            component["fileNotice"] = file_info["notice"]
        if "contributor" in file_info:
            for contributor in file_info["contributor"]:
                if "fileContributor" in component:
                    component["fileContributor"].append(contributor)
                else:
                    component["fileContributor"] = [contributor]
        # self.file_component.append(component)
        self.create_file(component)

    def generateJSONLicenseDetails(self, id, name, license_text, comment):
        extractedlicense = {}
        if len(id) > 0:
            extractedlicense["licenseId"] = id
        if len(name) > 0:
            extractedlicense["name"] = name
        if len(license_text) > 0:
            extractedlicense["extractedText"] = license_text
        if len(comment) > 0:
            extractedlicense["comment"] = comment
        self.licenses.append(extractedlicense)

    def generatePackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        self.generateJSONPackageDetails(
            package, id, package_info, parent_id, relationship
        )

    def generateFileDetails(self, file, id, file_info, parent_id, relationship):
        self.generateJSONFileDetails(file, id, file_info, parent_id, relationship)

    def addLicenseDetails(self, user_licenses):
        for license in user_licenses:
            self.license_info.append(
                {
                    "id": license["id"],
                    "name": license.get("name", ""),
                    "text": license.get("text", ""),
                    "comment": license.get("comment", ""),
                }
            )

    def generateLicenseDetails(self):
        for license_info in self.license_info:
            self.generateJSONLicenseDetails(
                license_info.get("id", ""),
                license_info.get("name", ""),
                license_info.get("text", ""),
                license_info.get("comment", ""),
            )

    def generateRelationship(self, from_id, to_id, relationship_type):
        # May need to update id to refer to SPDX document.
        if self.SPDX_PROJECT_ID in from_id:
            from_id = self.bom_id
        if (
            from_id != to_id
            and [from_id, to_id, relationship_type] not in self.relationship
        ):
            self.relationship.append([from_id, to_id, relationship_type])

    def showRelationship(self):
        # self.relationship.sort()
        for r in self.relationship:
            relation = dict()
            relation["spdxElementId"] = r[0]
            relation["relatedSpdxElement"] = r[1]
            relation["relationshipType"] = r[2].strip()
            self.relationships.append(relation)
            self.create_relationship(relation)
