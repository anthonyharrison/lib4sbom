import os
import json
import sys
from lib4sbom.data.identifier import SBOMIdentifier

# Use this to create the rules to validate PURLs against the PURL spec. The directory should be the 'types' directory which contains the JSON definitions

def extract_rules_from_directory(directory_path):
    purl_types = {}
    # Iterate through the files
    for filename in os.listdir(directory_path):
        if filename.endswith(".json"):
            file_path = os.path.join(directory_path, filename)

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    element = {}
                    element["namespace"] = "P"
                    if "namespace_definition" in data:
                        element["namespace"] = data["namespace_definition"]["requirement"][0].capitalize()
                    element["version"] = "O"
                    if "version_definition" in data:
                        element["version"] = data["version_definition"]["requirement"][0].capitalize()
                    element["subpath"] = "O"
                    if "subpath_definition" in data:
                        element["subpath"] = data["subpath_definition"]["requirement"][0].capitalize()
                    element["qualifiers"] = []
                    if "qualifiers_definition" in data:
                        for qualifier in data["qualifiers_definition"]:
                            element["qualifiers"].append(qualifier["key"])
                    purl_types[data["type"]] = element

            except (json.JSONDecodeError, IOError) as e:
                print(f"Skipping {filename}: {e}")

    return dict(sorted(purl_types.items()))

folder = sys.argv[1]
filename = sys.argv[2]
purl_rules = extract_rules_from_directory(folder)
with open(filename, "w") as f:
    f.write ("# This file has been auto-generated - DO NOT EDIT\n\n")
    f.write("# Copyright (C) 2026 Anthony Harrison\n")
    f.write("# SPDX-License-Identifier: Apache-2.0\n\n")
    f.write("# Rule Definitions (N=Namespace, V=Version, S=Subpath, Q=Qualifiers)\n")
    f.write("# R = Required, O = Optional, P = Prohibited\n\n")
    f.write(f"RULES = {purl_rules}\n")
