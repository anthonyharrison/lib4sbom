from lib4sbom.parser import SBOMParser

standard_file = "samples/asvs-5.cdx.json"
test_parser = SBOMParser()
test_parser.parse_file(standard_file)
definitions = test_parser.get_definitions()
print("Defintions", len(definitions))
for definition in definitions:
    for requirement in definition.get("requirement"):
        print (requirement)
    for level in definition.get("level"):
        print (level)
    for extref in definition.get("externalreference"):
        print (extref)
