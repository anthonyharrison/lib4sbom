# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from packageurl import PackageURL

class SBOMIdentifier:

    # Rule Definitions (N=Namespace, V=Version, S=Subpath, Q=Qualifiers)
    # R = Required, O = Optional, P = Prohibited
    RULES = {
        "alpm":                 {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["arch"]},
        "apk":                  {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["arch"]},
        "bazel":                {"namespace": "P", "version": "R", "subpath": "O", "qualifiers": ["repository_url"]},
        "bitbucket":            {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": []},
        "bitnami":              {"namespace": "P", "version": "R", "subpath": "P", "qualifiers": ["arch", "distro"]},
        "cargo":                {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": []},
        "cocoapods":            {"namespace": "P", "version": "O", "subpath": "O", "qualifiers": []},
        "composer":             {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": []},
        "conan":                {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": ["user", "channel", "rrev", "prev"]},
        "conda":                {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": ["build", "channel", "subdir", "type"]},
        "cpan":                 {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["repository_url", "download_url", "vcs_url", "ext"]},
        "cran":                 {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": []},
        "deb":                  {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["arch"]},
        "docker":               {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": []},
        "gem":                  {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": ["platform"]},
        "generic":              {"namespace": "O", "version": "P", "subpath": "P", "qualifiers": ["download_url", "checksum"]},
        "github":               {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": []},
        "golang":               {"namespace": "R", "version": "O", "subpath": "O", "qualifiers": []},
        "hackage":              {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": []},
        "hex":                  {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": []},
        "huggingface":          {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": []},
        "julia":                {"namespace": "P", "version": "P", "subpath": "P", "qualifiers": ["uuid"]},
        "luarocks":             {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": ["repository_url"]},
        "maven":                {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["classifier", "type"]},
        "mlflow":               {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": ["model_uuid", "run_id"]},
        "npm":                  {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": []},
        "nuget":                {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": []},
        "oci":                  {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": ["arch", "repository_url", "tag"]},
        "opam":                 {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": []},
        "otp":                  {"namespace": "P", "version": "O", "subpath": "O", "qualifiers": ["repository_url", "platform", "arch"]},
        "pub":                  {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": []},
        "pypi":                 {"namespace": "P", "version": "O", "subpath": "P", "qualifiers": ["file_name"]},
        "qpkg":                 {"namespace": "R", "version": "P", "subpath": "P", "qualifiers": []},
        "rpm":                  {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["epoch", "arch"]},
        "swid":                 {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": ["tag_id", "tag_version", "patch", "tag_creator_name", "tag_creator_regid"]},
        "swift":                {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": []},
        "vscode-extension":     {"namespace": "R", "version": "O", "subpath": "P", "qualifiers": ["platform"]},
        "yocto":                {"namespace": "O", "version": "O", "subpath": "P", "qualifiers": ["repository_url", "layer_version"]},
    }

    def __init__(self, purl_identifier):
        self.identifier = None
        self.errors = []
        self.fixed_parts = {}
        self.purl_identifer = purl_identifier.strip()

    def validate(self):
        # Scheme Validation
        if not self.purl_identifer.startswith("pkg:"):
            self.errors.append(f"PURL identifier must always start with pkg")
            return False

        try:
            # Parse using the library (handles normalization/encoding)
            p = PackageURL.from_string(self.purl_identifer)
        except ValueError as e:
            self.errors.append(f"Invalid PURL: {self.purl_identifer}")
            return False

        # Store component parts to enable correction
        self.fixed_parts = {
            "type": p.type,
            "namespace": p.namespace,
            "name": p.name,
            "version": p.version,
            "qualifiers": p.qualifiers or {},
            "subpath": p.subpath
        }

        # Type Validation
        rules = self.RULES.get(p.type)
        if not rules:
            self.errors.append(f"Unknown PURL type: {p.type}")
            return False

        # Name Validation
        if len(p.name) == 0:
            self.errors.append(f"Name is mandatory for: {p.type}")
            # return False

        # Namespace Validation
        if rules["namespace"] == "R" and not p.namespace:
            self.errors.append(f"Namespace is required for {p.type}")
        elif rules["namespace"] == "P" and p.namespace:
            self.errors.append(f"Namespace is prohibited for {p.type}")
            self.fixed_parts["namespace"] = None

        # Version Validation
        if rules["version"] == "R" and not p.version:
            self.errors.append(f"Version is required for {p.type}")
        elif rules["version"] == "P" and p.version:
            self.errors.append(f"Version is prohibited for {p.type}")
            self.fixed_parts["version"] = None

        # Subpath Validation
        if rules["subpath"] == "P" and p.subpath:
            self.errors.append(f"Subpath is prohibited for {p.type}")
            self.fixed_parts["subpath"] = None

        # Qualifier Validation
        if p.qualifiers:
            clean_quals = {k: v for k, v in p.qualifiers.items() if k in rules["qualifiers"]}
            if len(clean_quals) < len(p.qualifiers):
                removed = set(p.qualifiers.keys()) - set(clean_quals.keys())
                self.errors.append(f"Prohibited qualifiers removed: {', '.join(removed)}")
            self.fixed_parts["qualifiers"] = clean_quals

        return len(self.errors) == 0

    def get_errors(self):
        return self.errors

    def fix(self):
        if len(self.fixed_parts) > 0:
            fixed_purl = PackageURL(**self.fixed_parts)
            return fixed_purl.to_string()
        return ""

if __name__ == '__main__':

    # --- Testing ---
    test_purls = [
        "purl:pypi/numpy@0.12.4",
        "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
        "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources",
        "pkg:npm/foobar@12.3.1",
        "pkg:pypi/django@3.2?file_name=django.whl&invalid_param=true", # Qualifier fix
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0",           # Valid
        "pkg:npm/my-app#src/index.js",                                 # Subpath prohibited
        "pkg:pypi",
        "pkg:python:numpy@2.3",
        "pkg:",
        ""
    ]

    for test in test_purls:
        purl_validator = SBOMIdentifier(test)
        is_valid = purl_validator.validate()
        fixed_purl = purl_validator.fix()
        purl_errors = purl_validator.get_errors()
        print (f"Validating: {test}")
        print (f"\tValid: {is_valid}")
        if len(purl_errors) > 0:
            for error in purl_errors:
                print (f"\t Error: {error}")
            if len(fixed_purl) > 0:
                print (f"\t Fixed: {fixed_purl}")
        elif fixed_purl != test:
            print (f"Purl mismatch: {test} {fixed_purl}")