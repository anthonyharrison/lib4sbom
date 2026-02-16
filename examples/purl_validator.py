from lib4sbom.data.identifier import SBOMIdentifier

import os
from pathlib import Path

def validate(file_path, content):
    purl_validator = SBOMIdentifier(content)
    is_valid = purl_validator.validate()
    fixed_purl = purl_validator.fix()
    purl_errors = purl_validator.get_errors()
    # print (content, is_valid, fixed_purl, purl_errors)
    if is_valid:
        print (f"Valid: {content}")
        return
    if len(purl_errors) > 0:
        print (f"Invalid PURL: {content}")
        for error in purl_errors:
            print (f"\t Error: {error}")
        if len(fixed_purl) > 0:
            print (f"\t Fixed: {fixed_purl}")
    elif fixed_purl != content:
        print (f"Purl mismatch: {content} {fixed_purl}")

def process_directory(directory_path):
    # Convert string path to a Path object
    base_dir = Path(directory_path)

    # Check if directory exists
    if not base_dir.is_dir():
        print(f"Error: {directory_path} is not a valid directory.")
        return

    # Iterate through all .txt files in the directory
    for file_path in base_dir.glob('*.txt'):
        try:
            # Open and read the file content
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line in lines:
                validate(file_path, line.strip())

        except Exception as e:
            print(f"Could not process {file_path.name}: {e}")

if __name__ == "__main__":
    target_folder = '/data/Documents/purlvalidator-go/cmd/data'
    process_directory(target_folder)