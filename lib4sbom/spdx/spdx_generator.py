# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import uuid
from datetime import datetime

from lib4sbom.license import LicenseScanner
from lib4sbom.version import VERSION


class SPDXGenerator:
    """
    Generate SPDX Tag/Value SBOM.
    """

    SPDX_VERSION = "SPDX-2.3"
    DATA_LICENSE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    FILE_PREAMBLE = "SPDXRef-File-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        validate_license: True,
        spdx_format="tag",
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
        if self.format == "tag":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
            self.file_component = []
            self.relationships = []
        self.include_purl = False

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        if self.format != "tag":
            # Add subcomponents to SBOM
            if len(self.file_component) > 0:
                self.doc["files"] = self.file_component
            self.doc["packages"] = self.component
            self.doc["relationships"] = self.relationships
        return self.doc

    def getRelationships(self):
        return self.relationship

    def generateTag(self, tag, value):
        if value is not None:
            self.show(tag + ": " + value)
        else:
            print(f"[ERROR] with value for {tag}")

    def generateComment(self, comment):
        self.show("##### " + comment)

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateTagDocumentHeader(self, project_name):
        # Geerate SPDX Document Header
        self.generateTag("SPDXVersion", self.SPDX_VERSION)
        self.generateTag("DataLicense", self.DATA_LICENSE)
        self.generateTag("SPDXID", self.SPDX_PROJECT_ID)
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.generateTag("DocumentName", project_name.replace(" ", "-"))
        self.generateTag(
            "DocumentNamespace",
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + str(uuid.uuid4()),
        )
        self.generateTag("LicenseListVersion", self.license.get_license_version())
        self.generateTag(
            "Creator: Tool", self.application + "-" + self.application_version
        )
        self.generateTag("Created", self.generateTime())
        self.generateTag(
            "CreatorComment",
            "<text>This document has been automatically generated.</text>",
        )
        return self.SPDX_PROJECT_ID

    def generateJSONDocumentHeader(self, project_name):
        # Generate SPDX Document Header
        self.doc["SPDXID"] = self.SPDX_PROJECT_ID
        self.doc["spdxVersion"] = self.SPDX_VERSION
        creation_info = dict()
        creation_info["comment"] = "This document has been automatically generated."
        creation_info["creators"] = [
            "Tool: " + self.application + "-" + self.application_version
        ]
        creation_info["created"] = self.generateTime()
        creation_info["licenseListVersion"] = self.license.get_license_version()
        self.doc["creationInfo"] = creation_info
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.doc["name"] = project_name.replace(" ", "-")
        self.doc["dataLicense"] = self.DATA_LICENSE
        self.doc["documentNamespace"] = (
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + str(uuid.uuid4())
        )
        # self.doc["documentDescribes"]=[self.SPDX_PROJECT_ID]
        return self.SPDX_PROJECT_ID

    def generateDocumentHeader(self, project_name):
        # Assume a new document being created
        if self.format == "tag":
            self.doc = []
            return self.generateTagDocumentHeader(project_name)
        else:
            self.doc = {}
            self.component = []
            self.file_component = []
            self.relationships = []
            return self.generateJSONDocumentHeader(project_name)

    def package_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self.PACKAGE_PREAMBLE + str(id).replace(" ", "-").replace("_", "-")
        return str(id)

    def file_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self.FILE_PREAMBLE + str(id).replace(" ", "-").replace("_", "-")
        return str(id)

    def license_ident(self, license):
        if self.validate_license:
            if license != "UNKNOWN":
                derived_license = self.license.find_license(license)
                if derived_license != "UNKNOWN":
                    return derived_license
        return "NOASSERTION"

    def _file_name(self, name):
        # ensure name is a relative filename
        if name.startswith("/"):
            return name
        elif name.startswith("./"):
            return name
        else:
            return "./" + name

    def generateTagPackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        self.generateComment("\n")
        self.generateTag("PackageName", package)
        package_id = self.package_ident(id)
        self.generateTag("SPDXID", package_id)
        if "version" in package_info:
            version = package_info["version"]
            self.generateTag("PackageVersion", version)
        else:
            print(f"[WARNING] **** version missing for {package}")
        if "supplier" in package_info:
            if package_info["supplier_type"] != "UNKNOWN":
                # Supplier name mustn't have spaces in. Covert spaces to '_'
                self.generateTag(
                    "PackageSupplier",
                    package_info["supplier_type"]
                    + ": "
                    + package_info["supplier"].replace(" ", "_"),
                )
            else:
                self.generateTag("PackageSupplier", "NOASSERTION")
        if "originator" in package_info:
            # Originator mustn't have spaces in. Covert spaces to '_'
            self.generateTag(
                "PackageOriginator",
                package_info["originator_type"]
                + ": "
                + package_info["originator"].replace(" ", "_"),
            )
        self.generateTag(
            "PackageDownloadLocation",
            package_info.get("downloadlocation", "NOASSERTION"),
        )
        files_analysed = package_info.get("filesanalysis", False)
        self.generateTag("FilesAnalyzed", str(files_analysed).lower())
        if "filename" in package_info:
            self.generateTag("PackageFileName", package_info["filename"])
        if "homepage" in package_info:
            self.generateTag("PackageHomePage", package_info["homepage"])
        if "checksum" in package_info:
            # Potentially multiple entries
            for checksum in package_info["checksum"]:
                self.generateTag("PackageChecksum", checksum[0] + ": " + checksum[1])
        if "sourceinfo" in package_info:
            self.generateTag("PackageSourceInfo", package_info["sourceinfo"])
        if "licenseconcluded" in package_info:
            # self.generateComment("Reported license " + package_info["licenseconcluded"])
            self.generateTag(
                "PackageLicenseConcluded",
                self.license_ident(package_info["licenseconcluded"]),
            )
        if "licensedeclared" in package_info:
            self.generateTag(
                "PackageLicenseDeclared",
                self.license_ident(package_info["licensedeclared"]),
            )
        if "licensecomments" in package_info:
            self.generateTag("PackageLicenseComments", package_info["licensecomments"])
        if files_analysed:
            # Only if files have been analysed
            if "licenseinfoinfiles" in package_info:
                for info in package_info["licenseinfoinfiles"]:
                    self.generateTag(
                        "PackageLicenseInfoFromFiles",
                        self.license_ident(info),
                    )
        if "copyrighttext" in package_info:
            self.generateTag("PackageCopyrightText", package_info["copyrighttext"])
        else:
            self.generateTag("PackageCopyrightText", "NOASSERTION")
        if "description" in package_info:
            self.generateTag("PackageDescription", package_info["description"])
        if "comment" in package_info:
            self.generateTag("PackageComment", package_info["comment"])
        if "summary" in package_info:
            self.generateTag("PackageSummary", package_info["summary"])
        if "externalreference" in package_info:
            # Potentially multiple entries
            for reference in package_info["externalreference"]:
                self.generateTag(
                    "ExternalRef",
                    reference[0] + " " + reference[1] + " " + reference[2],
                )
        self.generateRelationship(
            self.package_ident(parent_id), package_id, relationship
        )

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
        else:
            print(f"[WARNING] **** version missing for {package}")
        if "supplier" in package_info:
            if package_info["supplier_type"] != "UNKNOWN":
                # Supplier name mustn't have spaces in. Covert spaces to '_'
                component["supplier"] = (
                    package_info["supplier_type"]
                    + ": "
                    + package_info["supplier"].replace(" ", "_")
                )
            else:
                component["supplier"] = "NOASSERTION"
        if "originator" in package_info:
            # Originator mustn't have spaces in. Covert spaces to '_'
            component["originator"] = (
                package_info["originator_type"]
                + ": "
                + package_info["originator"].replace(" ", "_")
            )
        component["downloadLocation"] = package_info.get(
            "downloadlocation", "NOASSERTION"
        )
        files_analysed = package_info.get("filesanalysis", False)
        component["filesAnalyzed"] = files_analysed
        if "filename" in package_info:
            component["packageFileName"] = package_info["filename"]
        if "homepage" in package_info:
            component["homepage"] = package_info["homepage"]
        if "checksum" in package_info:
            # Potentially multiple entries
            for checksum in package_info["checksum"]:
                checksum_entry = dict()
                checksum_entry["algorithm"] = checksum[0]
                checksum_entry["checkumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "sourceinfo" in package_info:
            component["sourceInfo"] = package_info["sourceinfo"]
        if "licenseconcluded" in package_info:
            component["licenseConcluded"] = self.license_ident(
                package_info["licenseconcluded"]
            )
        if "licensedeclared" in package_info:
            component["licenseDeclared"] = self.license_ident(
                package_info["licensedeclared"]
            )
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
        component["copyrightText"] = package_info.get("copyrightText", "NOASSERTION")
        if "description" in package_info:
            component["description"] = package_info["description"]
        if "comment" in package_info:
            component["comment"] = package_info["comment"]
        if "summary" in package_info:
            component["summary"] = package_info["summary"]
        component["downloadLocation"] = package_info.get("downloadLocation", "NONE")
        if "externalreference" in package_info:
            # Potentially multiple entries
            for reference in package_info["externalreference"]:
                reference_data = dict()
                reference_data["referenceCategory"] = reference[0]
                reference_data["referenceType"] = reference[1]
                reference_data["referenceLocator"] = reference[2]
                if "externalRefs" in component:
                    component["externalRefs"].append(reference_data)
                else:
                    component["externalRefs"] = [reference_data]
        self.component.append(component)
        self.generateRelationship(
            self.package_ident(parent_id), package_id, relationship
        )

    def generateTagFileDetails(self, file, id, file_info, parent_id, relationship):
        self.generateComment("\n")
        self.generateTag("FileName", self._file_name(file))
        file_id = self.file_ident(id)
        self.generateTag("SPDXID", file_id)
        if "checksum" in file_info:
            # Potentially multiple entries
            for checksum in file_info["checksum"]:
                self.generateTag("FileChecksum", checksum[0] + ": " + checksum[1])
        if "filetype" in file_info:
            for type in file_info["filetype"]:
                self.generateTag("FileType", type)
        if "licenseconcluded" in file_info:
            # self.generateComment("Reported license " + file_info["licenseconcluded"])
            self.generateTag(
                "LicenseConcluded", self.license_ident(file_info["licenseconcluded"])
            )
        if "licenseinfoinfile" in file_info:
            for info in file_info["licenseinfoinfile"]:
                self.generateTag("LicenseInfoInFile", self.license_ident(info))
        if "licensecomment" in file_info:
            self.generateTag("LicenseComments", file_info["licensecomment"])
        if "copyrighttext" in file_info:
            self.generateTag("FileCopyrightText", file_info["copyrighttext"])
        if "comment" in file_info:
            self.generateTag("FileComment", file_info["comment"])
        if "notice" in file_info:
            self.generateTag("FileNotice", file_info["notice"])
        if "contributor" in file_info:
            for contributor in file_info["contributor"]:
                self.generateTag("FileContributor", contributor)
        self.generateRelationship(self.package_ident(parent_id), file_id, relationship)

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
                checksum_entry["checkumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "comment" in file_info:
            component["fileComment"] = file_info["comment"]
        if "notice" in file_info:
            component["fileNotice"] = file_info["notice"]
        if "contributor" in file_info:
            for contributor in file_info["contributor"]:
                if "fileContributor" in component:
                    component["fileContributor"].append(contributor)
                else:
                    component["fileContributor"] = [contributor]
        self.file_component.append(component)
        self.generateRelationship(self.package_ident(parent_id), file_id, relationship)

    def generatePackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        if self.format == "tag":
            self.generateTagPackageDetails(
                package, id, package_info, parent_id, relationship
            )
        else:
            self.generateJSONPackageDetails(
                package, id, package_info, parent_id, relationship
            )

    def generateFileDetails(self, file, id, file_info, parent_id, relationship):
        if self.format == "tag":
            self.generateTagFileDetails(file, id, file_info, parent_id, relationship)
        else:
            self.generateJSONFileDetails(file, id, file_info, parent_id, relationship)

    def generateRelationship(self, from_id, to_id, relationship_type):
        if (
            from_id != to_id
            and [from_id, to_id, relationship_type] not in self.relationship
        ):
            self.relationship.append([from_id, to_id, relationship_type])

    def showRelationship(self):
        self.relationship.sort()
        for r in self.relationship:
            if self.format == "tag":
                self.generateTag("Relationship", f"{r[0]} {r[2].strip()} {r[1]}")
            else:
                relation = dict()
                relation["spdxElementId"] = r[0]
                relation["relatedSpdxElement"] = r[1]
                relation["relationshipType"] = r[2].strip()
                self.relationships.append(relation)
