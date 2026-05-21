# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMDefinition:
    def __init__(self):
        self.initialise()

    def _validate(self, attribute, value):
        if len(value) > 0:
            self.definition[attribute] = value 

    def initialise(self):
        self.definition = {}

    def set_id(self, id):
        self._validate("id", id)       

    def set_name(self, name):
        self._validate("name", name)
    
    def set_version(self, version):
        self._validate("version", version)

    def set_description(self, description):
        self._validate("description", description)

    def set_owner(self, owner):
        self._validate("owner", owner)

    def set_requirement(self, requirement_id, requirement_title, requirement_text, parent=None):
        requirement_entry = [requirement_id, requirement_title, requirement_text, parent]
        if "requirement" in self.definition:
            self.definition["requirement"].append(requirement_entry)
        else:
            self.definition["requirement"] = [requirement_entry]

    def set_level(self, level_id, level_title, level_description, level_requirements):
        level_entry = [level_id, level_title, level_description, level_requirements]
        if "level" in self.definition:
            self.definition["level"].append(level_entry)
        else:
            self.definition["level"] = [level_entry]   

    def set_externalreference(self, ref_type, locator, comment=""):
        # Valid categories (CycloneDX)
        valid_categories = [
            "vcs",
            "issue-tracker",
            "website",
            "advisories",
            "bom",
            "mailing-list",
            "social",
            "chat",
            "documentation",
            "support",
            "source-distribution",
            "distribution",
            "distribution-intake",
            "license",
            "build-meta",
            "build-system",
            "release-notes",
            "security-contact",
            "model-card",
            "log",
            "configuration",
            "evidence",
            "formulation",
            "attestation",
            "threat-model",
            "adversary-model",
            "risk-assessment",
            "vulnerability-assertion",
            "exploitability-statement",
            "pentest-report",
            "static-analysis-report",
            "dynamic-analysis-report",
            "runtime-analysis-report",
            "component-analysis-report",
            "maturity-report",
            "certification-report",
            "codified-infrastructure",
            "quality-metrics",
            "poam",
            "electronic-signature",
            "digital-signature",
            "rfc-9116",
            "patent",
            "patent-family",
            "patent-assertion",
            "citation",
            "other",
        ]
        # Allow multiple entries
        if ref_type.lower() not in valid_categories:
            ref_type = "other"
        reference_entry = [ref_type.lower().strip(), locator, comment]
        if "externalreference" in self.definition:
            self.definition["externalreference"].append(reference_entry)
        else:
            self.definition["externalreference"] = [reference_entry]

    def get(attribute, default_value=""):
        return self.definition.get(attribute, default_value)

    def get_definition(self):
        return self.definition

    def debug_definition(self):
        print("OUTPUT:", self.definition)

    def show_definition(self):
        for key in self.definition:
            print(f"{key}    : {self.definition[key]}")
