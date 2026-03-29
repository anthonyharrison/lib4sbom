# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX Crypto element

from lib4sbom.data.cryptography import SBOMCryptography
from lib4sbom.data.package import SBOMPackage
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOM

# Create packages
sbom_packages = {}
my_package = SBOMPackage()
my_package.set_name("glibc")
my_package.set_version("2.15")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("almalinux")
my_package.set_type("operating-system")
my_package.set_version("9.0")
my_package.set_supplier("organisation", "alma")
my_package.set_licensedeclared("Apache-2.0")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("tomcat")
my_package.set_version("9.0.46")
my_package.set_supplier("organisation", "apache")
my_package.set_licensedeclared("Apache-2.0")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
# Duplicated data
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_property("language", "C")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
#### This overwrites the package (same name and version)
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

my_crypto = SBOMCryptography()
# Include crypto with a component
my_package.initialise()
my_package.set_name("RSA-PKCS1-1.5-SHA-256-2048")
my_package.set_type("cryptographic-asset")
my_crypto.initialise()
my_crypto.set_oid("1.3.4.5.6")
my_crypto.set_type("algorithm","signature")
my_crypto.set_keysize("2048")
my_crypto.set_algorithm("RSASSA-PKCS1")
my_crypto.set_value("elipticCurve","bn/bn158")
# print(dict(my_crypto.get_cryptography()))
# Add crypto element to component
my_package.set_value("crypto", my_crypto.get_cryptography())

sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# Include crypto with a component
my_package.initialise()
my_package.set_name("Wikipedia-cert",)
my_package.set_type("cryptographic-asset")
my_crypto.initialise()
my_crypto.set_type("certificate")
my_crypto.set_certificate(subject = "C=US, ST=California, O=San Fransico, O=Wikipedia",
issuer='C=BE, O=GlbalSign, CN=Acme')
my_crypto.set_state("pre-activation")
my_crypto.set_date("create", "2026-02-13")
my_crypto.set_date("activate", "2026-02-14")
my_crypto.set_asset("publickey","abcd")
my_crypto.set_format("X.509")
my_package.set_value("crypto", my_crypto.get_cryptography())

sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# Include crypto with a component
my_package.initialise()
my_package.set_name("Wikipedia",)
my_package.set_type("cryptographic-asset")
my_crypto.initialise()
my_crypto.set_type("protocol", "tls")
my_crypto.set_version("1.3")
my_crypto.set_asset("publickey","abcd")
my_package.set_value("crypto", my_crypto.get_cryptography())

sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# Include crypto with a component
my_package.initialise()
my_package.set_name("WikipediaData",)
my_package.set_type("cryptographic-asset")
my_crypto.initialise()
my_crypto.set_type("related-crypto-material", "private-key")
my_crypto.set_state("active")
my_crypto.set_date("activate", "2026-02-16")
my_crypto.set_asset("privatekey","abcd")
my_package.set_value("crypto", my_crypto.get_cryptography())

sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()


# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="cyclonedx")
my_sbom.add_packages(sbom_packages)

# print(my_sbom.get_sbom())
#
my_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Will be displayed on console
my_generator.generate("MLApp", my_sbom.get_sbom())

# Send to file
