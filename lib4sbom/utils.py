# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0
import unicodedata
import re

def format_supplier(supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        MAX_SUPPLIER_LENGTH = 1024
        # And convert byte object to a string
        supplier_info = supplier_info[MAX_SUPPLIER_LENGTH]
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"(?<![a-z0-9!#$%&'*+/=?^_`{|}~-])((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
            re.IGNORECASE,
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())