import json
import sys
from rdflib import Graph

def parse_jsonld_simple(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    # Accessing the context or specific fields
    context = data.get('@context')
    graph = data.get('@graph', [data]) # JSON-LD can be a single object or a @graph list

    for item in graph:
        # print (dict(item))
        # print(f"ID: {item.get('@id')} | Type: {item.get('@type')}")
        # print (f"{item.get('type')} {item.get('creationInfo')} {item.get('spdxId')}")
        element_type = item.get('type')
        if element_type == "software_Package":
            for key, value in item.items():
                print (f"\t{key} : {value}")
        elif element_type == "CreationInfo":
            print (dict(item))
        elif element_type == "Tool":
            print (dict(item))
        elif element_type == "ExternalIdentifier":
            print (dict(item))

def parse_jsonld_semantic(file_path):
    # Create an RDF Graph
    g = Graph()

    # Parse the JSON-LD file
    # format="json-ld" is built into modern rdflib
    try:
        g.parse(file_path, format="json-ld")

        print(f"Graph has {len(g)} triples.\n")

        # Iterate through triples: Subject, Predicate, Object
        for s, p, o in g:
            print(f"Subject: {s}\nPredicate: {p}\nObject: {o}\n{'-'*20}")

    except Exception as e:
        print(f"Error parsing JSON-LD: {e}")

filename = sys.argv[1]
parse_type = sys.argv[2]

if parse_type =="simple":
    parse_jsonld_simple(filename)
else:
    parse_jsonld_semantic(filename)
# Example usage
# parse_jsonld_simple('data.jsonld')