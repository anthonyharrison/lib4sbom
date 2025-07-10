# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
from typing import Dict, List

from lib4sbom.cyclonedx.cyclonedx_parser import CycloneDXParser
from lib4sbom.exception import SBOMParserException
from lib4sbom.sbom import SBOM, ParserType, SBOMData
from lib4sbom.spdx.spdx_parser import SPDXParser


class SBOMParser:
    """
    Simple SBOM Parser.

    Parameters
    ----------
    sbom_type : string
        The type of SBOM (either spdx, cyclonedx or auto)

        auto is used to automatically work out the SBOM type

        Default is auto
    """

    def __init__(self, sbom_type: str = "auto"):
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        self.sbom_type = sbom_type
        self.document = None
        self.files = None
        self.packages = None
        self.relationships = None
        self.vulnerabilities = None
        self.services = None
        self.licenses = None
        self.sbom = SBOM(self.sbom_type)

    def parse_file(self, filename: str) -> None:
        """Parses a SBOM file

        Parameters
        ----------
        filename : string
            The filename of the SBOM
        """
        # Check file exists
        invalid_file = True
        if len(filename) > 0:
            # Check path
            filePath = Path(filename)
            # Check path exists, a valid file and not empty file
            if filePath.exists() and filePath.is_file() and filePath.stat().st_size > 0:
                # Assume that processing can proceed
                invalid_file = False

        if invalid_file:
            raise FileNotFoundError

        # Determine parser type
        if filename.endswith((".bom.json", ".cdx.json")):
            parser_type = ParserType.CYCLONEDX_JSON
        elif filename.endswith((".bom.xml", ".cdx.xml", ".xml")):
            parser_type = ParserType.CYCLONEDX_XML

        elif filename.endswith(".spdx"):
            parser_type = ParserType.SPDX_TAG
        elif filename.endswith(".spdx.json"):
            parser_type = ParserType.SPDX_JSON
        elif filename.endswith((".spdx.yaml", "spdx.yml")):
            parser_type = ParserType.SPDX_YML
        elif filename.endswith(".spdx.rdf"):
            parser_type = ParserType.SPDX_RDF
        elif filename.endswith(".spdx.xml"):
            parser_type = ParserType.SPDX_XML
        elif filename.endswith(".json"):
            # Convention for SPDX is to use .spdx.json extension but
            # check any json file just in case. Attempts to parse a CycloneDX JSON
            # file will result in no data being returned.
            parser_type = ParserType.JSON
        else:
            raise SBOMParserException

        with open(filename, "r", encoding="utf-8") as f:
            sbom_string = f.read()
        self._parse_sbom(sbom_string, parser_type)

    def parse_string(self, sbom_string: str) -> None:
        """Parses a SBOM string

        Parameters
        ----------
        sbom_string : string
            SBOM content
        """
        canonical_string = sbom_string.strip()
        self._parse_sbom(canonical_string, None)

    def _parse_sbom(self, sbom_string: str, parser_type: ParserType = None) -> None:
        """Parses a SBOM file or string

        Parameters
        ----------
        sbom_string : string
            SBOM content
        parser_type : ParserType
            Parser type
        """
        # Set up parser
        if self.sbom_type == "cyclonedx":
            self.parser = CycloneDXParser()
        else:
            # Default parser is SPDX
            self.parser = SPDXParser()

        try:
            if self.sbom_type == "auto":
                # Work out the SBOM type for file
                # Assume SPDX...
                self.sbom_type = "spdx"
                (
                    self.document,
                    self.files,
                    self.packages,
                    self.relationships,
                    self.vulnerabilities,
                    self.services,
                    self.licenses,
                ) = self.parser.parse(sbom_string, parser_type)
                # but if no packages or files found, assume it must be CycloneDX
                if (
                    len(self.packages) == 0
                    and len(self.files) == 0
                    and len(self.vulnerabilities) == 0
                ):
                    self.sbom_type = "cyclonedx"
                    self.parser = CycloneDXParser()
                    (
                        self.document,
                        self.files,
                        self.packages,
                        self.relationships,
                        self.vulnerabilities,
                        self.services,
                        self.licenses,
                    ) = self.parser.parse(sbom_string, parser_type)
            else:
                (
                    self.document,
                    self.files,
                    self.packages,
                    self.relationships,
                    self.vulnerabilities,
                    self.services,
                    self.licenses,
                ) = self.parser.parse(sbom_string, parser_type)
            self.sbom.add_files(self.files)
            self.sbom.add_packages(self.packages)
            self.sbom.add_relationships(self.relationships)
            if len(self.document) > 0:
                self.sbom.add_document(self.document.get_document())
            if len(self.vulnerabilities) > 0:
                self.sbom.add_vulnerabilities(self.vulnerabilities)
            if len(self.services) > 0:
                self.sbom.add_services(self.services)
            if len(self.licenses) > 0:
                self.sbom.add_licenses(self.licenses)
            self.sbom.set_type(self.sbom_type)
        except KeyError:
            if self.debug:
                print("Key Error")
            raise SBOMParserException
        except TypeError:
            if self.debug:
                print("Type Error")
            raise SBOMParserException

    def set_type(self, sbom_type: str = "auto") -> None:
        self.sbom_type = sbom_type

    def get_sbom(self) -> SBOMData:
        """Return the constituent components of SBOM
        Returns
        -------
        SBOM : SBOMData object
        """
        return self.sbom.get_sbom()

    def get_type(self) -> str:
        """Return the type of SBOM
        Returns
        -------
        SBOMtype : string
        """
        return self.sbom.get_type()

    def get_files(self) -> List[Dict]:
        """Returns the file elements from within a parsed SBOM
        Returns
        -------
        files : list of SBOMfile objects

        """
        return self.sbom.get_files()

    def get_packages(self) -> List[Dict]:
        """Returns the package elements from within a parsed SBOM
        Returns
        -------
        packages : list of SBOMPackage objects

        """
        return self.sbom.get_packages()

    def get_relationships(self) -> List[List[str]]:
        """Returns the relationship elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMRelationship objects

        """
        return self.sbom.get_relationships()

    def get_document(self) -> Dict:
        """Returns the relationship elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMDocument objects

        """
        return self.sbom.get_document()

    def get_vulnerabilities(self) -> List[Dict]:
        """Returns the vulnerability elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMVulnerability objects

        """
        return self.sbom.get_vulnerabilities()

    def get_services(self) -> List[Dict]:
        """Returns the service elements from within a parsed SBOM
        Returns
        -------
        services : list of SBOMService objects

        """
        return self.sbom.get_services()

    def get_licenses(self) -> List[Dict]:
        """Returns the license elements from within a parsed SBOM
        Returns
        -------
        licenses : list of SBOMLicense objects

        """
        return self.sbom.get_licenses()
