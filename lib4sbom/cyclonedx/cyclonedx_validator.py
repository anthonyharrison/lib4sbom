# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
from pathlib import Path
from urllib.parse import urlparse

import fastjsonschema
import xmlschema


class CycloneDXValidator:

    CYCLONEDX_VERSIONS = ["1.7", "1.6", "1.5", "1.4", "1.3"]
    SUPPORT_SCHEMA = ["spdx.schema.json", "jsf-0.82.schema.json"]
    BASE_URI = "http://cyclonedx.org/schema/"

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

    def _load_schema_with_local_refs(self, schema_file, local_dir):
        # Load a CycloneDX schema JSON file and rewrite to point to local schema files.
        schema_file = Path(schema_file)
        local_dir = Path(local_dir)
        with open(schema_file, "r") as f:
            schema = json.load(f)

        def rewrite_refs(obj):
            if isinstance(obj, dict):
                if "$id" in obj or "$ref" in obj:
                    key = "$id" if "$id" in obj else "$ref"
                    uri = obj[key]
                    # Check if the URI is a local, relative path (not an external URL)
                    # It handles cases like `file.json` or `../path/file.json`
                    if not urlparse(uri).scheme:
                        ref_name = Path(uri).name
                        local_ref = local_dir / ref_name
                        if local_ref.exists():
                            obj[key] = f"file://{str(local_ref.resolve())}"
                            if self.debug:
                                print(
                                    f"[JSON] {key} - {local_ref} resolved to {obj[key]}"
                                )
                for v in obj.values():
                    rewrite_refs(v)
            elif isinstance(obj, list):
                for i in obj:
                    rewrite_refs(i)

        rewrite_refs(schema)
        return schema

    def validate_cyclonedx_json(self, sbom_file):
        sbom_data = json.load(open(sbom_file))
        for cyclonedx_version in self.cyclonedx_version:
            schema_file = f"{self.schemas_path}/bom-{cyclonedx_version}.schema.json"
            if self.debug:
                print(
                    f"[JSON] Checking to validate against CycloneDX {cyclonedx_version}."
                )
            # Validate SBOM
            try:
                schema = self._load_schema_with_local_refs(
                    schema_file, self.schemas_path
                )
                validate = fastjsonschema.compile(schema, detailed_exceptions=True)
                validate_result = validate(sbom_data)
                # if a validation error occurs, won't get here
                if self.debug:
                    print(f"Result from validate: {validate_result}")
                return {"CycloneDX": cyclonedx_version}
            except Exception as e:
                if self.debug:
                    print(
                        f"[ValidationError] Failed to validate against CycloneDX {cyclonedx_version} JSON schema.\n{e}"
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
