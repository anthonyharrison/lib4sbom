# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import jsonschema
import yaml


class SPDXValidator:

    SPDX_VERSIONS = ["2.3", "2.2"]

    def __init__(self, spdx_version=None, debug=False):
        self.debug = debug
        self.spdx_version = (
            self.SPDX_VERSIONS if spdx_version is None else [spdx_version]
        )
        self.schemas_path = Path(__file__).resolve().parent.parent / "schemas" / "spdx"

    def validate(self, sbom_file):
        """validates SPDX SBOM file"""
        if sbom_file.endswith(".spdx"):
            return self.validate_spdx_tag(sbom_file)
        elif sbom_file.endswith((".spdx.json", ".json")):
            # Convention for SPDX is to use .spdx.json extension but
            # check any json file just in case. Attempts to validate a CycloneDX JSON
            # file will result in no data being returned.
            return self.validate_spdx_json(sbom_file)
        elif sbom_file.endswith((".spdx.yaml", ".spdx.yml")):
            return self.validate_spdx_yaml(sbom_file)
        elif sbom_file.endswith(".spdx.rdf"):
            return self.validate_spdx_rdf(sbom_file)
        elif sbom_file.endswith(".spdx.xml"):
            return self.validate_spdx_xml(sbom_file)
        else:
            return {"SPDX": "Unknown"}

    def validate_spdx_tag(self, sbom_file):
        # Simple validation performed
        with open(sbom_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            if line.startswith("SPDXVersion"):
                for spdx_version in self.spdx_version:
                    if self.debug:
                        print(
                            f"[TAG] Checking to validate against SPDX {spdx_version}."
                        )
                    if spdx_version in line:
                        return {"SPDX": spdx_version}
                break
        return {"SPDX": False}

    def _validate_jsonyaml_data(self, sbom_data):
        for spdx_version in self.spdx_version:
            schema_file = f"{self.schemas_path}/{spdx_version}-schema.json"
            if self.debug:
                print(f"[JSON] Checking to validate against SPDX {spdx_version}.")
            try:
                jsonschema.validate(
                    instance=sbom_data, schema=json.load(open(schema_file))
                )
                # if no validation errors
                return {"SPDX": spdx_version}
            except jsonschema.exceptions.SchemaError:
                if self.debug:
                    print(
                        f"[Schema Error] Failed to validate against SPDX {spdx_version} JSON schema"
                    )
            except jsonschema.exceptions.ValidationError:
                if self.debug:
                    print(
                        f"[ValidationError] Failed to validate against SPDX {spdx_version} JSON schema"
                    )
        return {"SPDX": False}

    def validate_spdx_json(self, sbom_file):
        sbom_data = json.load(open(sbom_file))
        # Might be in a protobuf
        if sbom_data.get("sbom") is not None:
            sbom_dict = sbom_data["sbom"]
        # Might be an Into attestation
        if sbom_data.get("predicateType"):
            if "spdx.dev/Document" in sbom_data.get("predicateType"):
                sbom_data = sbom_data.get("predicate")
        return self._validate_jsonyaml_data(sbom_data)

    def validate_spdx_yaml(self, sbom_file):
        sbom_data = yaml.safe_load(open(sbom_file, "r", encoding="utf-8"))
        return self._validate_jsonyaml_data(sbom_data)

    def validate_spdx_rdf(self, sbom_file):
        # Simple validation performed
        with open(sbom_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            if line.strip().startswith("<spdx:specVersion>"):
                for spdx_version in self.spdx_version:
                    if self.debug:
                        print(
                            f"[RDF] Checking to validate against SPDX {spdx_version}."
                        )
                    if spdx_version in line:
                        return {"SPDX": spdx_version}
                break
        return {"SPDX": False}

    def validate_spdx_xml(self, sbom_file):
        # Simple validation performed
        with open(sbom_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            if line.strip().startswith("<spdxVersion>"):
                for spdx_version in self.spdx_version:
                    if self.debug:
                        print(
                            f"[XML] Checking to validate against SPDX {spdx_version}."
                        )
                    if spdx_version in line:
                        return {"SPDX": spdx_version}
                break
        return {"SPDX": False}
