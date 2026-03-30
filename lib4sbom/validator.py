# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from lib4sbom.cyclonedx.cyclonedx_validator import CycloneDXValidator
from lib4sbom.exception import SBOMValidatorException
from lib4sbom.spdx.spdx_validator import SPDXValidator


class SBOMValidator:
    """
    Simple SBOM Validatorr.

    Parameters
    ----------
    sbom_type : string
        The type of SBOM (either spdx, cyclonedx or auto)

        auto is used to automatically work out the SBOM type

        Default is auto
    """

    def __init__(self, sbom_type: str = "auto", version=None, debug=False):
        self.sbom_type = sbom_type
        self.version = version
        self.debug = debug

    def validate_file(self, filename: str) -> None:
        """Validates a SBOM file

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

        # Set up parser
        if self.sbom_type == "cyclonedx":
            self.validator = CycloneDXValidator(
                cyclonedx_version=self.version, debug=self.debug
            )
        else:
            # Default validator is SPDX
            self.validator = SPDXValidator(spdx_version=self.version, debug=self.debug)

        try:
            if self.sbom_type == "auto":
                # Work out the SBOM type for file
                # Assume SPDX...
                self.sbom_type = "spdx"
                validate = self.validator.validate(filename)
                # but if fails, check if it is a CycloneDX SBOM
                if validate["SPDX"] is False:
                    self.sbom_type = "cyclonedx"
                    self.validator = CycloneDXValidator(
                        cyclonedx_version=self.version, debug=self.debug
                    )
                    validate = self.validator.validate(filename)
            else:
                validate = self.validator.validate(filename)
        except KeyError:
            if self.debug:
                print("Key Error")
            raise SBOMValidatorException
        except TypeError:
            if self.debug:
                print("Type Error")
            raise SBOMValidatorException
        return validate
