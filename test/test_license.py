import pytest

from lib4sbom.license import LicenseScanner as test_module


class TestLicenseScanner:

    # Initialisation checks
    def test_initialise(self):
        tm = test_module()
        assert len(tm.get_license_list()) > 0

    def test_getlicense_version(self):
        tm = test_module()
        assert len(tm.get_license_version()) > 0

    # Synonymn checks
    def test_check_synonym(self):
        tm = test_module()
        assert tm.check_synonym("GPL2+") != None

    def test_check_missing_synonym(self):
        tm = test_module()
        assert tm.check_synonym("NotaLicence") == None

    # Find license checks

    @pytest.mark.parametrize(
        "license, expected_result",
        (
            ("", "NOASSERTION"),
            (None, "NOASSERTION"),
            ("NOASERTION", "NOASSERTION"),
            ("UNKNOWN", "NOASSERTION"),
            ("NONE", "NONE"),
            ("MIT/Apache-2.0", "MIT OR Apache-2.0"),
            ("Apache-2.0/MIT", "Apache-2.0 OR MIT"),
            ("Unlicense/MIT", "Unlicense OR MIT"),
            ("MIT/Unlicense", "MIT OR Unlicense"),
            ("MIT or Apache-2.0", "MIT OR Apache-2.0"),
            ("MIT And Apache-2.0", "MIT AND Apache-2.0"),
            ("NotALicense", "NOASSERTION"),
            ("Adaptive Public License 1.0", "APL-1.0"),
            ("Apache-2.0 with LLVM-exception", "Apache-2.0 WITH LLVM-exception"),
            ("Apache 2.0 with LLVM-exception", "Apache-2.0 WITH LLVM-exception"),
            ("Apache 2.0 with LLVM Exception", "Apache-2.0 WITH LLVM-exception"),
            ("NotALicence with My Exception", "NOASSERTION"),
            ("Apache-2.0 WITH My Exception", "NOASSERTION"),
            ("LicenseRef-MyLic", "LicenseRef-MyLic"),
            ("GPL2+", "GPL-2.0-or-later"),
            ("wxWindows","wxWindows"),  # Deprecated license
            ("Apache-1.0+", "Apache-1.0+"),
            ("NotALicence+", "NOASSERTION"),
            ("Apache-1.0+ WITH LLVM-exception", "Apache-1.0+ WITH LLVM-exception"),
        ),
    )
    def test_license(self, license, expected_result):
        tm = test_module()
        result = tm.find_license(license)
        assert result == expected_result

    @pytest.mark.parametrize(
        "expression, expected_result",
        (
            ("", False),
            ("MIT or Apache-2.0", True),
            ("MIT And Apache-2.0", True),
            ("MIT AND Apache-2.0", True),
            ("MIT", False),
            ("Apache-2.0 with LLVM Exception", False),
            ("MIT AND Apache-1.0+", True),
        ),
    )

    def test_license_expresion(self, expression, expected_result):
        tm = test_module()
        result = tm.license_expression(expression)
        assert result == expected_result

    @pytest.mark.parametrize(
        "exception, expected_result",
        (
            ("", False),
            ("MIT And Apache-2.0 WITH LLVM-expetion", True),
            ("MIT AND Apache-2.0", False),
            ("MIT", False),
            ("Apache-2.0 with LLVM-exception", True),
            ("Apache-1.0+ WITH LLVM-exception", True),
        ),
    )

    def test_license_exception(self, exception, expected_result):
        tm = test_module()
        result = tm.license_exception(exception)
        assert result == expected_result

    @pytest.mark.parametrize(
        "license, expected_result",
        (
            ("MIT", False),
            ("Apache-1.0+", True),
        ),
    )
    def test_orlater(self, license, expected_result):
        tm = test_module()
        result = tm.orlater(license)
        assert result == expected_result

    # Get routines

    def test_get_license_text(self):
        tm = test_module()
        result = tm.get_license_text("NotALicence")
        assert len(result) == 0
        result = tm.get_license_text("MIT")
        assert len(result) > 0
        result = tm.get_license_text("Apache-1.0+")
        assert len(result) > 0

    def test_get_license_name(self):
        tm = test_module()
        result = tm.get_license_name("NotALicence")
        assert result == ""
        result = tm.get_license_name("MIT")
        assert result == "MIT License"
        result = tm.get_license_name("MIT+")
        assert result == "MIT License"

    def test_get_license_url(self):
        tm = test_module()
        result = tm.get_license_url("NotALicence")
        assert result is None
        result = tm.get_license_url("UNKNOWN")
        assert result is None
        result = tm.get_license_url("MIT")
        assert result.startswith("http")
        result = tm.get_license_url("Apache-2.0 WITH LLVM-exception")
        assert result.startswith("http")
        result = tm.get_license_url("Apache-1.0+")
        assert result.startswith("http")

    def test_osi_approved(self):
        tm = test_module()
        result = tm.osi_approved("NotALicence")
        assert result == False
        result = tm.osi_approved("UNKNOWN")
        assert result is False
        result = tm.osi_approved("MIT")
        assert result == True
        result = tm.osi_approved("Apache-1.0")
        assert result == False
        result = tm.osi_approved("MIT+")
        assert result == True

    def test_get_license_from_exception(self):
        tm = test_module()
        result = tm.get_license_from_exception("NotALicence")
        assert result == None
        result = tm.get_license_from_exception("Apache-2.0")
        assert result is None
        result = tm.get_license_from_exception("Apache-2.0 WITH LLVM-exception")
        assert result == "Apache-2.0"
        result = tm.get_license_from_exception("Apache-1.0+")
        assert result is None


    def test_get_exception(self):
        tm = test_module()
        result = tm.get_exception("NotALicence")
        assert result == None
        result = tm.get_exception("Apache-2.0")
        assert result is None
        result = tm.get_exception("Apache-2.0 WITH LLVM-exception")
        assert result == "LLVM-exception"
        result = tm.get_exception("Apache-1.0+")
        assert result is None

    def test_get_exception_text(self):
        tm = test_module()
        result = tm.get_exception_text("Apache-2.0")
        assert len(result) == 0
        result = tm.get_exception_text("LLVM-exception")
        assert len(result) > 0
        result = tm.get_exception_text("Apache-1.0+")
        assert len(result) == 0

    def test_get_exception_url(self):
        tm = test_module()
        result = tm.get_exception_url("Apache-2.0")
        assert result is None
        result = tm.get_exception_url("Apache-1.0+")
        assert result is None
        result = tm.get_exception_url("LLVM-exception")
        assert result.startswith("http")

    @pytest.mark.parametrize(
        "license, expected_result",
        (
            ([], "unknown"),
            (["AGPL-3.0"], "networkcopyleft"),
            (["MIT"],"permissive"),
            (["NotALicence"], "unknown"),
            (["MIT","Apache-2.0"], "permissive"),
            (["MIT","GPL-3.0+"], "copyleft"),
            (["Apache-2.0 WITH LLVM-exception"], "permissive"),
            (["Apache-1.0+"], "permissive"),
        ),
    )
    def test_get_license_category(self, license, expected_result):
        tm = test_module()
        result = tm.get_license_category(license)
        assert result == expected_result.upper()

    @pytest.mark.parametrize(
        "spdxid, expected_result",
        (
            ("", False),
            ("AGPL-3.0", True),
            ("MIT", True),
            ("UnKNOWN", False),
            ("Apache 2.0", False),
            ("Apache-2.0 WITH LLVM-exception", False),
            ("Apache-1.0+", False),
        ),
    )
    def test_valid_SPDX_id (self, spdxid, expected_result):
        tm = test_module()
        result = tm.valid_spdx_license(spdxid)
        assert result == expected_result

    @pytest.mark.parametrize(
        "expression, expected_result",
        (
            ("", []),
            ("MIT or Apache-2.0", ["MIT", "Apache-2.0"]),
            ("MIT And Apache-2.0", ["MIT", "Apache-2.0"]),
            ("MIT AND Apache-2.0", ["MIT", "Apache-2.0"]),
            ("MIT AND Apache-1.0+", ["MIT", "Apache-1.0+"]),
            ("MIT", ["MIT"]),
            ("MIT AND NotALicence", ["MIT", "NOASSERTION"]),
            ("Apache-2.0 with LLVM Exception", ["Apache-2.0 WITH LLVM-exception"]),
            ("Apache-2.0 WITH LLVM-exception OR MIT", ["Apache-2.0 WITH LLVM-exception", "MIT"]),
        ),
    )
    def test_expresiion_list(self, expression, expected_result):
        tm = test_module()
        result = tm.expression_license_list(expression)
        assert result == expected_result
