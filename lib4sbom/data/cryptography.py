# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime
from pathlib import Path


class SBOMCryptography:

    alg_type_cdx = [
        {
            "type": "algorithm",
            "option": [
                "drbg",
                "mac",
                "block-cipher",
                "stream-cipher",
                "signature",
                "hash",
                "pke",
                "xof",
                "kdf",
                "key-agree",
                "kem",
                "ae",
                "combiner",
                "key-wrap",
                "other",
                "unknown",
            ],
        },
        {"type": "certificate", "option": []},
        {
            "type": "protocol",
            "option": [
                "tls",
                "ssh",
                "ipsec",
                "ike",
                "sstp",
                "wpa",
                "dtls",
                "quic",
                "eap-aka",
                "eap-aka-prime",
                "prins",
                "5g-aka",
                "other",
                "unknown",
            ],
        },
        {
            "type": "related-crypto-material",
            "option": [
                "private-key",
                "public-key",
                "secret-key",
                "key",
                "ciphertext",
                "signature",
                "digest",
                "initialization-vector",
                "nonce",
                "seed",
                "salt",
                "shared-secret",
                "tag",
                "additional-data",
                "password",
                "credential",
                "token",
                "other",
                "unknown",
            ],
        },
    ]

    alg_type_spdx = [
        {
            "type": "Cryptographic-Hash-Function",
            "option": [
                "Hash-Function",
                "Password-Hashing",
                "Message-Authentication-Code",
                "Checksum",
            ],
        },
        {
            "type": "Symetric-Key-Algorithm",
            "option": [
                "Block-Cipher",
                "Stream-Cipher",
                "Encoding",
                "Random-Number-Generator",
                "Key-Derivation",
            ],
        },
        {
            "type": "Asymmetric-Key-Algorithm",
            "option": [
                "Public-Key-Encryption",
                "Public-Key-Cipher",
                "Elliptic-Curve-Cryptography",
                "Digital-Signature",
                "Post-Quantum-Cryptography",
                "Protocol",
                "Hybrid-Cipher",
                "Key-Exchange-Mechanism",
            ],
        },
    ]

    def __init__(self):
        self.cryptography = {}
        # Read crypto files
        self.cyclonedx_crypto_config_file = (
            Path(__file__).resolve().parent.parent
            / "schemas"
            / "cyclonedx"
            / "cryptography-defs.schema.json"
        )
        self.spdx_path = None
        self.algorithm_family = {}

    def _read_cdx(self, schema_path):
        with open(schema_path, encoding="utf-8") as schema_file:
            cdx_data = json.load(schema_file)
        for algorithm in cdx_data["algorithms"]:
            if "variant" in algorithm and "primitive" in algorithm["variant"]:
                self.algorithm_family[algorithm["family"]] = algorithm["variant"][
                    "primitive"
                ]

    def initialise(self):
        if len(self.algorithm_family) == 0:
            self._read_cdx(self.cyclonedx_crypto_config_file)
        self.cryptography = {}

    def set_id(self, id):
        self.cryptography["id"] = id

    def set_type(self, crypto_type, crypto_attribute=""):
        # only for CycloneDX
        for alg_class in self.alg_type_cdx:
            key = alg_class["type"]
            options = alg_class["option"]
            if len(options) > 0:
                if crypto_type == key and crypto_attribute in options:
                    self.cryptography["type"] = key
                    self.cryptography["primitive"] = crypto_attribute
                    break
            elif crypto_type == key:
                self.cryptography["type"] = key
                break

    # Algorithm attributes

    def set_algorithm(self, algorithm):
        # cdx
        # check algorithm family matches primitive
        if self.cryptography["type"] == "algorithm":
            alg_family = self.algorithm_family.get(algorithm)
            if alg_family is not None and self.cryptography["primitive"] == alg_family:
                self.cryptography["algorithm"] = algorithm

    def set_keysize(self, keysize):
        self.cryptography["keysize"] = keysize

    # Certificate attributes

    def _validate_date(self, date_value):
        try:
            datetime.fromisoformat(date_value)
            return True
        except ValueError:
            return False

    def set_certificate(self, subject=None, issuer=None):
        if subject is not None:
            self.cryptography["subject"] = subject
        if issuer is not None:
            self.cryptography["issuer"] = issuer

    def set_format(self, cert_format):
        if len(cert_format) > 0:
            self.cryptography["format"] = cert_format

    def set_date(self, date_event, date_value):
        valid_event = {
            "create": "creationDate",
            "activate": "activationDate",
            "update": "updateDate",
            "expire": "expirationDate",
            "deactivate": "deactivationDate",
            "revoke": "revocationDate",
            "destroy": "destructionDate",
        }
        event = valid_event[date_event]
        if event is not None and self._validate_date(date_value):
            self.cryptography[event] = date_value

    def set_state(self, certificate_state):
        if certificate_state.lower() in [
            "pre-activation",
            "active",
            "suspended",
            "deactivated",
            "revoked",
            "destroyed",
        ]:
            self.cryptography["state"] = certificate_state.lower()

    def set_asset(self, asset_type, asset_value):
        # Allow multiple entries
        asset_entry = {"type": asset_type.strip(), "ref": asset_value}
        if "relatedCryptographicAssets" in self.cryptography:
            self.cryptography["relatedCryptographicAssets"].append(asset_entry)
        else:
            self.cryptography["relatedCryptographicAssets"] = [asset_entry]

    # Protocol

    def set_version(self, version):
        self.cryptography["version"] = version

    # Crypto Material

    def set_cryptography_property(self, crypto_class, class_option):
        # only for SPDX
        for alg_class in self.alg_type_spdx:
            key = alg_class["type"]
            options = alg_class["option"]
            if crypto_class == key and class_option in options:
                self.cryptography["xxx"] = key
                self.cryptography["class"] = class_option
                break

    def set_value(self, atribute, attribute_value):
        self.cryptography[atribute] = attribute_value

    # def set_property(self, name, value):
    #     # Allow multiple entries
    #     property_entry = [name.strip(), value]
    #     if "property" in self.dataset:
    #         self.cryptography["property"].append(property_entry)
    #     else:
    #         self.Cryptography["property"] = [property_entry]

    def set_cryptography_reference(self, reference):
        self.cryptography["reference"] = reference

    def set_oid(self, oid):
        self.cryptography["oid"] = oid

    def get_value(self, attribute, default_value=None):
        return self.cryptography.get(attribute, default_value)

    def get_cryptography(self):
        return self.cryptography

    def debug_cryptography(self):
        print("OUTPUT:", self.cryptography)

    def show_cryptography(self):
        for key in self.cryptography:
            print(f"{key}    : {self.cryptography[key]}")
