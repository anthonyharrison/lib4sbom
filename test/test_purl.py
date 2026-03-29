import os
import json
import sys
from lib4sbom.data.identifier import SBOMIdentifier

# Use this to validate the examples in the PURL spec. The directory should be the 'types' directory which contains the JSON definitions

def extract_elements_from_directory(directory_path, target_key):
    all_extracted_items = []
    # Iterate through the files
    for filename in os.listdir(directory_path):
        if filename.endswith(".json"):
            file_path = os.path.join(directory_path, filename)

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    # Extract the element (handles both single objects and lists)
                    extracted = data.get(target_key, [])

                    if isinstance(extracted, list):
                        all_extracted_items.extend(extracted)
                    else:
                        all_extracted_items.append(extracted)

            except (json.JSONDecodeError, IOError) as e:
                print(f"Skipping {filename}: {e}")

    return all_extracted_items

folder = sys.argv[1]
key_to_find = 'examples'

examples = extract_elements_from_directory(folder, key_to_find)
print(f"Total items extracted: {len(examples)}")

# Now process the examples aand report any which are invalid
for content in examples:
    purl_validator = SBOMIdentifier(content)
    if not purl_validator.validate():
        print (f"{content} is reported as invalid")
        print (purl_validator.get_errors())