# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
from pathlib import Path

import jsonschema
import xmlschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


class CycloneDXValidator:

    CYCLONEDX_VERSIONS = ["1.3", "1.4", "1.5", "1.6"]
    SUPPORT_SCHEMA = ["spdx.schema.json", "jsf-0.82.schema.json"]

    def __init__(self, cyclonedx_version=None, debug=False):
        self.debug = debug
        self.cyclonedx_version = (
            self.CYCLONEDX_VERSIONS
            if cyclonedx_version is None
            else [cyclonedx_version]
        )
        self.schemas_path = (
            Path(__file__).resolve().parent.parent / "schemas" / "cyclonedx"
        )

    def validate(self, sbom_file):
        """parses CycloneDX BOM file extracting package name, version and license"""
        if sbom_file.endswith((".bom.json", ".cdx.json", ".json")):
            return self.validate_cyclonedx_json(sbom_file)
        elif sbom_file.endswith((".bom.xml", ".cdx.xml", ".xml")):
            return self.validate_cyclonedx_xml(sbom_file)
        else:
            return {"CycloneDX": "Unknown"}

    def _load_supporting_schema(self, uri):
        filename = f"{self.schemas_path}/{uri}"
        schema = json.load(open(filename))
        resource = Resource(contents=schema, specification=DRAFT7)
        return (uri, resource)

    def validate_cyclonedx_json(self, sbom_file):
        sbom_data = json.load(open(sbom_file))
        for cyclonedx_version in self.cyclonedx_version:
            schema_file = f"{self.schemas_path}/bom-{cyclonedx_version}.schema.json"
            base_schema = json.load(open(schema_file))
            # Load supporting schemas
            resources = []
            for schema_uri in self.SUPPORT_SCHEMA:
                resources.append(self._load_supporting_schema(schema_uri))
            registry = Registry().with_resources(resources)
            if self.debug:
                print(
                    f"[JSON] Checking to validate against CycloneDX {cyclonedx_version}."
                )
            try:
                validator = jsonschema.Draft7Validator(base_schema, registry=registry)
                validator.validate(sbom_data)
                # if no validation errors
                return {"CycloneDX": cyclonedx_version}
            except jsonschema.exceptions.SchemaError:
                if self.debug:
                    print(
                        f"[Schema Error] Failed to validate against CycloneDX {cyclonedx_version} JSON schema"
                    )
            except jsonschema.exceptions.ValidationError:
                if self.debug:
                    print(
                        f"[ValidationError] Failed to validate against CycloneDX {cyclonedx_version} JSON schema"
                    )
        return {"CycloneDX": False}

    def validate_cyclonedx_xml(self, sbom_file):
        for cyclonedx_version in self.cyclonedx_version:
            schema_sources = [
                f"{self.schemas_path}/bom-{cyclonedx_version}.xsd",
                f"{self.schemas_path}/spdx.xsd",
            ]
            if self.debug:
                print(
                    f"[XML] Checking to validate against CycloneDX {cyclonedx_version}."
                )
            try:
                # Suppress output to stderr
                with contextlib.redirect_stderr(None):
                    schema = xmlschema.XMLSchema(schema_sources)
                    if schema.is_valid(sbom_file):
                        return {"CycloneDX": cyclonedx_version}
                    elif self.debug:
                        print(
                            f"[Schema Error] Failed to validate against Cyclone.DX {cyclonedx_version} XML schema"
                        )
            except xmlschema.exceptions.XMLSchemaKeyError:
                if self.debug:
                    print(
                        f"[Schema Error] Failed to validate against CycloneDX {cyclonedx_version} XML schema"
                    )
        return {"CycloneDX": False}
