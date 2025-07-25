# Lib4SBOM

Lib4SBOM is a library to parse and generate Software Bill of Materials (SBOMs). It supports SBOMs created in both
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org) formats.

It has been developed on the assumption that having a generic abstraction of SBOM regardless of the underlying format will be useful to developers.

The following facilities are provided:

- Generate SPDX SBOM in TagValue, JSON and YAML formats
- Generate CycloneDX SBOM in JSON format
- Parse SPDX SBOM in TagValue, JSON, YAML, XML and RDF formats
- Validate CycloneDX SBOM in JSON and XML format
- Validate SPDX SBOM in TagValue, JSON, YAML, XML and RDF formats
- Parse CycloneDX SBOM in JSON and XMLformat
- Create and manipulate a SBOM file object
- Create and manipulate a SBOM package object
- Create and manipulate a SBOM dependency relationship object
- Create and manipulate a Vulnerability object
- Create and manipulate a Software Service object
- Generated SBOM can be output to a file or to the console

## Installation

To install use the following command:

`pip install lib4sbom`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## API

### SBOMParser

The SBOMParser module provides methods for parsing a SBOM in either SPDX or CycloneDX format and
returns the file, package and relationship information from within the SBOM.

The focus of the implementation is on providing a common set of SBOM data regardless of the SBOM format.

SBOMs are supported in the following formats and versions

| SBOM Type | Version | Format   |
| --------- |---------|----------|
| SPDX      | 2.2     | TagValue |
| SPDX      | 2.2     | JSON     |
| SPDX      | 2.2     | YAML     |
| SPDX      | 2.2     | RDF      |
| SPDX      | 2.2     | XML      |
| SPDX      | 2.3     | TagValue |
| SPDX      | 2.3     | JSON     |
| SPDX      | 2.3     | YAML     |
| SPDX      | 2.3     | RDF       |
| SPDX      | 2.3     | XML      |
| CycloneDX | 1.4     | JSON     |
| CycloneDX | 1.4     | XML      |
| CycloneDX | 1.5     | JSON     |
| CycloneDX | 1.5     | XML      |
| CycloneDX | 1.6     | JSON     |
| CycloneDX | 1.6     | XML      |

**Note** that support for SPDX RDF and XML formats is limited to a few package attributes.

_class_ **SBOMParser**(_sbom_type='auto_')

This creates a simple SBOM Parser object. A single optional parameter, _sbom_type_, can be specified
which represents the type of SBOM (either spdx, cyclonedx or auto). The default is auto in
which case the parser will automatically work out the SBOM type using the
following filename conventions.

| SBOM      | Format   | Filename extension |
| --------- |----------|--------------------|
| SPDX      | TagValue | .spdx              |
| SPDX      | JSON     | .spdx.json         |
| SPDX      | YAML     | .spdx.yaml         |
| SPDX      | YAML     | .spdx.yml          |
| SPDX      | RDF      | .spdx.rdf          |
| SPDX      | XML      | .spdx.xml          |
| CycloneDX | JSON     | .json              |
| CycloneDX | JSON     | .cdx.json          |
| CycloneDX | JSON     | .bom.json          |
| CycloneDX | XML      | .xml               |
| CycloneDX | XML      | .cdx.xml           |
| CycloneDX | XML      | .bom..xml          |

The parser will check that the correct JSON files is being processed by the correct parser.
A SPDX JSON file submitted to the CycloneDX parser will result in no data being processed.

Errors in the parsing process will result in the exception SBOMParserException being raised.

**Methods**

parse_file(filename)
Parses the SBOM file. If the file does not exist, a FileNotFoundError exception is raised.

If an error occurs during the parsing of the file, a SBOMParserException exception is raised.

parse_string(sbom_string)
Parses the SBOM content from sbom_string.

If an error occurs during the parsing of the file, a SBOMParserException exception is raised.

get_files()
Returns a list of file elements from within a parsed SBOM

get_packages()
Returns a list of packages elements from within a parsed SBOM

get_relationships()
Returns the relationship elements from within a parsed SBOM

get_vulnerabilities()
Returns the vulnerability elements from within a parsed SBOM

get_services()
Returns the software service elements from within a parsed SBOM

get_type()
Returns the type of SBOM (either spdx or cyclonedx)

**Example**

A test SBOM file (test_sbom.spdx) is used in the following example.

```bash
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: virtualenv
DocumentNamespace: http://spdx.org/spdxdocs/virtualenv-b7ac9cce-efe8-4fe7-a544-100e6a5664e6
LicenseListVersion: 3.18
Creator: Tool: sbom4python-0.4.0
Created: 2022-11-16T10:14:26Z
CreatorComment: <text>This document has been automatically generated.</text>
##### 

PackageName: virtualenv
SPDXID: SPDXRef-Package-1-virtualenv
PackageSupplier: Person: Bernat_Gabor
PackageVersion: 20.16.7
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/virtualenv@20.16.7
##### 

PackageName: distlib
SPDXID: SPDXRef-Package-2-distlib
PackageSupplier: Person: Vinay_Sajip
PackageVersion: 0.3.6
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/distlib@0.3.6
##### 

PackageName: filelock
SPDXID: SPDXRef-Package-3-filelock
PackageSupplier: Person: Benedikt_Schmitt
PackageVersion: 3.8.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: Unlicense
PackageLicenseDeclared: Unlicense
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/filelock@3.8.0
##### 

PackageName: platformdirs
SPDXID: SPDXRef-Package-4-platformdirs
PackageSupplier: NOASSERTION
PackageVersion: 2.5.4
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/platformdirs@2.5.4

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-1-virtualenv
Relationship: SPDXRef-Package-1-virtualenv CONTAINS SPDXRef-Package-2-distlib
Relationship: SPDXRef-Package-1-virtualenv CONTAINS SPDXRef-Package-3-filelock
Relationship: SPDXRef-Package-1-virtualenv CONTAINS SPDXRef-Package-4-platformdirs
```

The following code sample shows the use of the SBOMParser module.

```python
>>> from lib4sbom.parser import SBOMParser
>>> test_parser = SBOMParser()
>>> print (f"SBOM type {test_parser.get_type()}")                                                                                                                                             
SBOM type auto                                                                                                                                                                                
>>> test_parser.parse_file("test_sbom.spdx")                                                                                                                                                                                                                                                                                            
>>> print (f"SBOM type {test_parser.get_type()}")                                                                                                                                             
SBOM type spdx                                                                                                                                                                                
>>> sbom_files = test_parser.get_files()
>>> print (sbom_files)                                                                                                                                                                        
[]                                                                                                                                                                                            
>>> sbom_packages = test_parser.get_packages()
>>> print (sbom_packages)
[{'name': 'virtualenv', 'type': 'library', 'id': 'SPDXRef-Package-1-virtualenv', 'supplier_type': 'Person', 'supplier': 'Bernat_Gabor', 'version': '20.16.7', 'downloadlocation': 'NOASSERTION', 'filesanalysis': 'false', 'licenseconcluded': 'MIT', 'licensedeclared': 'MIT', 'externalreference': [['PACKAGE-MANAGER', 'purl', 'pkg:pypi/virtualenv@20.16.7']]}, {'name': 'distlib', 'type': 'library', 'id': 'SPDXRef-Package-2-distlib', 'supplier_type': 'Person', 'supplier': 'Vinay_Sajip', 'version': '0.3.6', 'downloadlocation': 'NOASSERTION', 'filesanalysis': 'false', 'licenseconcluded': 'NOASSERTION', 'licensedeclared': 'NOASSERTION', 'externalreference': [['PACKAGE-MANAGER', 'purl', 'pkg:pypi/distlib@0.3.6']]}, {'name': 'filelock', 'type': 'library', 'id': 'SPDXRef-Package-3-filelock', 'supplier_type': 'Person', 'supplier': 'Benedikt_Schmitt', 'version': '3.8.0', 'downloadlocation': 'NOASSERTION', 'filesanalysis': 'false', 'licenseconcluded': 'Unlicense', 'licensedeclared': 'Unlicense', 'externalreference': [['PACKAGE-MANAGER', 'purl', 'pkg:pypi/filelock@3.8.0']]}, {'name': 'platformdirs', 'type': 'library', 'id': 'SPDXRef-Package-4-platformdirs', 'supplier_type': 'Organization', 'supplier': 'Unknown', 'version': '2.5.4', 'downloadlocation': 'NOASSERTION', 'filesanalysis': 'false', 'licenseconcluded': 'NOASSERTION', 'licensedeclared': 'NOASSERTION', 'externalreference': [['PACKAGE-MANAGER', 'purl', 'pkg:pypi/platformdirs@2.5.4']]}]
>>> print (len(sbom_packages))
4
>>> sbom_packages[0]
{'name': 'virtualenv', 'type': 'library', 'id': 'SPDXRef-Package-1-virtualenv', 'supplier_type': 'Person', 'supplier': 'Bernat_Gabor', 'version': '20.16.7', 'downloadlocation': 'NOASSERTION', 'filesanalysis': 'false', 'licenseconcluded': 'MIT', 'licensedeclared': 'MIT', 'externalreference': [['PACKAGE-MANAGER', 'purl', 'pkg:pypi/virtualenv@20.16.7']]}
>>> sbom_relationships = test_parser.get_relationships()
>>> print (sbom_relationships)
[{'source': 'TestDocument', 'type': 'DESCRIBES', 'target': 'virtualenv', 'source_id': 'SPDXRef-DOCUMENT', 'target_id': 'SPDXRef-Package-1-virtualenv'}, {'source': 'virtualenv', 'type': 'CONTAINS', 'target': 'distlib', 'source_id': 'SPDXRef-Package-1-virtualenv', 'target_id': 'SPDXRef-Package-2-distlib'}, {'source': 'virtualenv', 'type': 'CONTAINS', 'target': 'filelock', 'source_id': 'SPDXRef-Package-1-virtualenv', 'target_id': 'SPDXRef-Package-3-filelock'}, {'source': 'virtualenv', 'type': 'CONTAINS', 'target': 'platformdirs', 'source_id': 'SPDXRef-Package-1-virtualenv', 'target_id': 'SPDXRef-Package-4-platformdirs'}]
>>> sbom_relationships[2]
{'source': 'virtualenv', 'type': 'CONTAINS', 'target': 'filelock', 'source_id': 'SPDXRef-Package-1-virtualenv', 'target_id': 'SPDXRef-Package-3-filelock'}
>>> 
```

_class_ **SBOMValidator**(_sbom_type='auto', version=None, debug=False_)

This creates a simple SBOM Validator object.

The optional parameter, _sbom_type_, can be specified
which represents the type of SBOM (either spdx, cyclonedx or auto). The default is auto in
which case the parser will automatically work out the SBOM type using the
following filename conventions.

| SBOM      | Format   | Filename extension |
| --------- |----------|--------------------|
| SPDX      | TagValue | .spdx              |
| SPDX      | JSON     | .spdx.json         |
| SPDX      | YAML     | .spdx.yaml         |
| SPDX      | YAML     | .spdx.yml          |
| SPDX      | RDF      | .spdx.rdf          |
| SPDX      | XML      | .spdx.xml          |
| CycloneDX | JSON     | .json              |
| CycloneDX | JSON     | .cdx.json          |
| CycloneDX | JSON     | .bom.json          |
| CycloneDX | XML      | .xml               |
| CycloneDX | XML      | .cdx.xml           |
| CycloneDX | XML      | .bom..xml          |

The optional parameter, _version_, can be used to specify a single version of the SBOM to be validated against e.g. "1.6".

The optional parameter, _debug_, can be used to generate debug output.

**Methods**

validate_file(filename)
Validates the SBOM file. If the file does not exist, a FileNotFoundError exception is raised.

The validator will check that the correct JSON files is being processed by the correct parser.
A SPDX JSON file submitted to the CycloneDX parser will result in no data being processed.

If an error occurs during the validation of the file, a SBOMValidatorException exception is raised.

The return value is a dictionary representing the type of SBOM and the version. e.g. {"SPDX" : 2.3}.
If the SBOM fails to validate the return value is the type of SBOM and a boolean value e.g. e.g. {"SPDX" : False}.
If the SBOM cannot be validated the return value is the type of SBOM and "Unknown" i.e. {"SPDX" : "Unknown"}.

Validation rules:
- The validation for SPDX JSON and YAML files is against the SPDX JSON schema.
- The validation for SPDX TagValue, RDF and XML files is simply vaerification that a valid version of the SDPX specification is detected.
- The validation for CycloneDX JSON files is against the CycloneDX JSON schema.
- The validation for CycloneDX XML files is against the CycloneDX XML schema.

### SBOMGenerator

The SBOMGenerator module provides methods for generating a SBOM in either SPDX or CycloneDX format.

The focus of the implementation is on providing a single interface regardless of the SBOM type and format.

SBOMs can be generated in the following formats

| SBOM Type | Version | Format    |
| --------- |---------| ----------|
| SPDX      | 2.2     | Tag       |
| SPDX      | 2.2     | JSON      |
| SPDX      | 2.2     | YAML      |
| SPDX      | 2.3     | Tag       |
| SPDX      | 2.3     | JSON      |
| SPDX      | 2.3     | YAML      |
| CycloneDX | 1.4     | JSON      |
| CycloneDX | 1.5     | JSON      |
| CycloneDX | 1.6     | JSON      |

The default version for CycloneDX is version 1.6. However, the version can be overridden by setting the environment variable LIB4SBOM_CYCLONEDX_VERSION to "1.4" if required.

The default version for SPDX is version 2.3. However, the version can be overridden by setting the environment variable LIB4SBOM_SPDX_VERSION to "SPDX-2.2" if required.

The organization creating the SBOM can be set be setting the environment variable SBOM_ORGANIZATION. This can be overriden by setting the value of the Metadata_Supplier attribute
within the SBOM Document.

_class_ **SBOMGenerator**(_validate_license: True, sbom_type="spdx", format="tag", application="lib4sbom", version="0.1"_)

This creates a simple SBOM Generator object. The following optional parameters can be specified:

_validate_license_ indicates if license information is validated against the set of [SPDX license identifiers](https://spdx.org/licenses/). This option only applies for SPDX SBOMs
as this is mandatory for CycloneDX SBOMs.

_sbom_type_ indicates the type of SBOM to be generated. Valid options are spdx or cyclonedx

_format_ indicates the format that the SBOM is to be generated in. Valid options are Tag, JSON or YAML. If an invalid format is specified,
a default format of JSON will be assumed. If an unsupported format is specified for the type of SBOM (e.g. Tag or YAML for CycloneDX), a default
format is assumed (Tag for SPDX, JSON for CycloneDX)

_application_ and _version_ specify the name and version of the tool which created the SBOM. If these are not specified, the application name is 'lib4sbom' and the version is '0.1'

**Methods**

_generate(project_name, sbom_data, filename = "", send_to_output = True)_

The method generates the SBOM file. The parameters are

_project_name_ specifies the name of the project

_sbom_data_ contain the SBOM data to be used in the generation. It contains details of the packages, files and relationships to be included in the SBOM.

_filename_ is the name of the file to be generated. The default is for the output to be generated to a console.

_send_to_output_ indicates if the output is to be sent to the filename.

get_sbom()
Returns the generated SBOM in the requested format

get_type()
Returns the type of the generated SBOM (either spdx or cyclonedx)

get_format()
Returns the format of the generated SBOM (one of tag, json or yaml)

**Example**

The following code sample shows the use of the SBOMGenerator module being used
in the conversion of a SBOM from the Tag Value format to YAML format. The output is sent ot the console.

```python
>>> from lib4sbom.parser import SBOMParser
>>> test_parser = SBOMParser()
>>> test_parser.parse_file("test_sbom.spdx")
>>> from lib4sbom.generator import SBOMGenerator
>>> test_generator = SBOMGenerator(format="yaml")
>>> test_generator.get_type()
'spdx'
>>> test_generator.get_format()
'yaml'
>>> test_generator.generate("TestApp",test_parser.get_sbom())
SPDXID: SPDXRef-DOCUMENT
creationInfo:
  comment: This document has been automatically generated.
  created: '2023-01-24T13:51:36Z'
  creators:
  - 'Tool: lib4sbom-0.1.0'
  licenseListVersion: '3.18'
dataLicense: CC0-1.0
documentNamespace: http://spdx.org/spdxdocs/TestDocument-817c4e4c-eac4-49d9-bc41-65f0972edce8
name: TestDocument
...
- relatedSpdxElement: SPDXRef-Package-4-platformdirs
  relationshipType: DESCRIBES
  spdxElementId: SPDXRef-DOCUMENT
- relatedSpdxElement: SPDXRef-Package-2-distlib
  relationshipType: CONTAINS
  spdxElementId: SPDXRef-Package-1-virtualenv
- relatedSpdxElement: SPDXRef-Package-3-filelock
  relationshipType: CONTAINS
  spdxElementId: SPDXRef-Package-1-virtualenv
- relatedSpdxElement: SPDXRef-Package-4-platformdirs
  relationshipType: CONTAINS
  spdxElementId: SPDXRef-Package-1-virtualenv
spdxVersion: SPDX-2.3
>>> test_generator.get_sbom()
{'SPDXID': 'SPDXRef-DOCUMENT', 'spdxVersion': 'SPDX-2.3', 'creationInfo': {'comment': 'This document has been automatically generated.', 'creators': ['Tool: lib4sbom-0.1.0'], 'created': '2023-01-24T13:51:36Z', 'licenseListVersion': '3.18'}, 'name': 'TestDocument', 'dataLicense': 'CC0-1.0', 'documentNamespace': 'http://spdx.org/spdxdocs/TestDocument-817c4e4c-eac4-49d9-bc41-65f0972edce8', 'packages': [{'SPDXID': 'SPDXRef-Package-1-virtualenv', 'name': 'virtualenv', 'versionInfo': '20.16.7', 'supplier': 'Person: Bernat_Gabor', 'downloadLocation': 'NONE', 'filesAnalyzed': 'false', 'licenseConcluded': 'MIT', 'licenseDeclared': 'MIT', 'copyrightText': 'NOASSERTION', 'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/virtualenv@20.16.7'}]}, {'SPDXID': 'SPDXRef-Package-2-distlib', 'name': 'distlib', 'versionInfo': '0.3.6', 'supplier': 'Person: Vinay_Sajip', 'downloadLocation': 'NONE', 'filesAnalyzed': 'false', 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION', 'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/distlib@0.3.6'}]}, {'SPDXID': 'SPDXRef-Package-3-filelock', 'name': 'filelock', 'versionInfo': '3.8.0', 'supplier': 'Person: Benedikt_Schmitt', 'downloadLocation': 'NONE', 'filesAnalyzed': 'false', 'licenseConcluded': 'Unlicense', 'licenseDeclared': 'Unlicense', 'copyrightText': 'NOASSERTION', 'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/filelock@3.8.0'}]}, {'SPDXID': 'SPDXRef-Package-4-platformdirs', 'name': 'platformdirs', 'versionInfo': '2.5.4', 'supplier': 'Organization: Unknown', 'downloadLocation': 'NONE', 'filesAnalyzed': 'false', 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION', 'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/platformdirs@2.5.4'}]}], 'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relatedSpdxElement': 'SPDXRef-Package-1-virtualenv', 'relationshipType': 'DESCRIBES'}, {'spdxElementId': 'SPDXRef-DOCUMENT', 'relatedSpdxElement': 'SPDXRef-Package-2-distlib', 'relationshipType': 'DESCRIBES'}, {'spdxElementId': 'SPDXRef-DOCUMENT', 'relatedSpdxElement': 'SPDXRef-Package-3-filelock', 'relationshipType': 'DESCRIBES'}, {'spdxElementId': 'SPDXRef-DOCUMENT', 'relatedSpdxElement': 'SPDXRef-Package-4-platformdirs', 'relationshipType': 'DESCRIBES'}, {'spdxElementId': 'SPDXRef-Package-1-virtualenv', 'relatedSpdxElement': 'SPDXRef-Package-2-distlib', 'relationshipType': 'CONTAINS'}, {'spdxElementId': 'SPDXRef-Package-1-virtualenv', 'relatedSpdxElement': 'SPDXRef-Package-3-filelock', 'relationshipType': 'CONTAINS'}, {'spdxElementId': 'SPDXRef-Package-1-virtualenv', 'relatedSpdxElement': 'SPDXRef-Package-4-platformdirs', 'relationshipType': 'CONTAINS'}]}
>>> 
```

### SBOMOutput

_class_ **SBOMOutput**(_filename="", output_format="tag"_)

This creates a simple SBOM Output object. The following optional parameters can be specified:

_filename_ indicates the output destination of the SBOM to be generated. If a valid filename path is provided and a file can be created, then the output will be to a file otherwise
it will be output to the console.

_output_format_ indicates the format that the SBOM is to be generated in. Valid options are Tag, JSON or YAML. If an invalid format is specified,
a default format of Tag will be assumed.

**Methods**

generate_output(dataset) Outputs a SBOM file. The parameters are

_dataset_ contains SBOM data in the output format. If the SBOM data is NOT in the format specified by the output_format parameter, no output will be generated.

**NOTE A valid dataset will normally be generated by the SBOMGenerator class and obtained by a call to the get_sbom() method.**

get_type()
Return the destination of the generated SBOM. Either file or console

get_format()
Return the format of the generated SBOM. One of Tag, JSON or YAML.

**Example**

The following code sample shows the use of the SBOMOutput module.

```python
>>> from lib4sbom.parser import SBOMParser
>>> test_parser = SBOMParser()
>>> test_parser.parse_file("test_sbom.spdx")
>>> from lib4sbom.generator import SBOMGenerator
>>> test_generator = SBOMGenerator(format="json")
>>> test_generator.generate("TestApp",test_parser.get_sbom())
>>> from lib4sbom.output import SBOMOutput
>>> sbom_output = SBOMOutput(filename="testapp.json", output_format="json")
>>> sbom_output.generate_output(test_generator.get_sbom())
>>> 
```

### SBOM Object 

_class_ **SBOM**()

This creates a simple SBOM object. This object contains all the items to be contained within the SBOM including
components and relationships. It is left to the application manipulating the SBOM object to apply validation as appropriate
for the presence of each attribute.

**Methods**

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_type(). Unless indicated, the method just takes a single parameter for the value. Where indicated, multiple instances of the attribute may be defined.

| Attribute         | Multiple | Note |
|-------------------|----------|------|
| Version           | No       | (1)  |
| Type              | No       | (2)  |
| Uuid              | No       | (3)  |
| Bom_Version       | No       |      |

**Note**

1. This relates to the version of the specification of SBOM specified by the type atrribute. e.g. 1.4 for CycloneDX, SPDX-2.3 for SPDX.

2. This refers to the type of SBOM either SPDX or CycloneDX.

3. This relates to the unique identifier for the SBOM.

**_Getter Methods_**

get_sbom()
Returns the SBOM object as a dictionary.

**Example**

```python
>>> from lib4sbom.sbom import SBOM
>>> sbom = SBOM()
>>> sbom.set_type(sbom_type='cyclonedx')
>>> sbom.set_version("1.4")
>>> sbom.set_uuid("urn:uuid:My_uuid_1234")
>>> sbom.set_bom_version("2")
>>> sbom.get_type()
'cyclonedx'
>>> from lib4sbom.data.document import SBOMDocument
>>> my_doc = SBOMDocument()
>>> my_doc.set_metadata_type("firmware")
>>> sbom.add_document(my_doc.get_document())
```

### SBOMDocument Object 

_class_ **SBOMDocument**()

This creates a simple SBOMDocument object. This object contains the values of the attributes
that can be associated with a SBOM. This includes attributes such as name, identifier, type of file,
checksum and licence information. As each of the attributes are optional, it is left to the application manipulating the
SBOMFile object to apply validation as appropriate for the presence of each attribute.

**Methods**

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_filetype(). The attribute names are aligned with the attributes of the File Object in the SPDX Specification. Unless
indicated, the method just takes a single parameter for the value. Where indicated, multiple instances of the attribute may be defined.

| Attribute         | Multiple | Note |
|-------------------|----------|------|
| Name              | No       |      |
| Id                | No       |      |
| DataLicense       | No       |      |
| Metadata_Type     | No       | (1)  |
| Metadata_Supplier | No       |      |
| Metadata_Version  | No       |      |
| Bom_Version       | No       |      |

**Note**

1. This relates to the type of component which the SBOM is describing. This is attribute is only used for CycloneDX SBOMs.

There is an additional setter method, **set_value**(_attribute, value_) which allows the setting of any attribute.

`set_value("language", "Rust")`

**_Getter Methods_**

get_document()
Returns the SBOMDocument object as a list.

get_name()
Returns the name of the SBOMDocument object or a default value if the attribute does not exist within the instance of the SBOMDocument object.

get_value(attribute)
Returns the value of the attribute. A default value is returned if the attribute does not exist within the instance of the SBOMDocument object.

**Example**

```python
>>> from lib4sbom.data.document import SBOMDocument
>>> sbom_document = SBOMDocument()
>>> sbom_document.set_name("test_file")
>>> sbom_document.set_metadata_type("firmware")
>>> sbom_document.get_name()
'test_file'
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_document(sbom_document.get_document())
```

### SBOMFile Object

_class_ **SBOMFile**()

This creates a simple SBOM File object. This object contains the values of the attributes
that can be associated with a file artefact within an SBOM. This includes attributes such as name, identifier, type of file,
checksum and licence information. As each of the attributes are optional, it is left to the application manipulating the
SBOMFile object to apply validation as appropriate for the presence of each attribute.

**Methods**

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_filetype(). The attribute names are aligned with the attributes of the File Object in the SPDX Specification. Unless
indicated, the method just takes a single parameter for the value. Where indicated, multiple instances of the attribute may be defined.

| Attribute         | Multiple | Note |
|-------------------|----------|------|
| Name              | No       |      |
| Id                | No       |      |
| FileType          | Yes      |      |
| Checksum          | Yes      | (1)  |
| LicenseConcluded  | No       |      |
| LicenceInfoInFile | Yes      |      |
| LicenceComment    | No       |      |
| CopyrightText     | No       |      |
| Comment           | No       |      |
| Notice            | No       |      |
| Contributor       | Yes      |      |
| Attribution       | No       |      |

**Note**

1. The set_checksum method takes two parameters, the checksum algorithm (e.g. SHA256) and the actual checksum value (as a string)

There is an additional setter method, **set_value**(_attribute, value_) which allows the setting of any attribute.

`set_value("language", "Rust")`

**_Getter Methods_**

get_file()
Returns the SBOMFile object as a dictionary. The value of an attribute is returned as a string except where multiple instances of an attribute are allowed in which
case the value of the attribute is returned as a List.

get_name()
Returns the name of the SBOMFile object or None if the 'name' attribute does not exist within the instance of the SBOMFile object.

get_value(attribute)
Returns the value of the attribute. A default value is returned if the attribute does not exist within the instance of the SBOMFile object.

_**Utility Methods**_

initialise() Reinitialises a SBOMFile Object. All data associated with the object is deleted.

**Example**

```python
>>> from lib4sbom.data.file import SBOMFile
>>> sbom_file = SBOMFile()
>>> sbom_files = {}
>>> sbom_file.initialise()
>>> sbom_file.set_name("test_file.c")
>>> sbom_file.set_licenseconcluded("MIT")
>>> file_hash = <<< some calculation >>>
>>> sbom_file.set_checksum("SHA1", file_hash)
>>> sbom_file.set_id("SPDXRef-File-0001")
>>> sbom_files[sbom_file.get_name()] = sbom_file.get_file()
>>> sbom_file.initialise()                                  
>>> sbom_file.set_name("makefile")                       
>>> sbom_file.set_licenseconcluded("NOASSERTION")                    
>>> sbom_file.set_id("SPDXRef-File-0002")                   
>>> sbom_files[sbom_file.get_name()] = sbom_file.get_file()
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_files(sbom_files)
```

### SBOMPackage Object
                
_class_ **SBOMPackage**()

This creates a simple SBOM Package object. This object contains the values of the attributes
that can be associated with a package or component artefact within an SBOM. This includes attributes such as name, identifier, supplier,
version and licence information. As each of the attributes are optional, it is left to the application manipulating the
SBOMPackage object to apply validation as appropriate for the presence of each attribute.

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_version(). The attribute names are aligned with the attributes of the Package Object in the SPDX Specification. Unless
indicated, the method just takes a single parameter for the value. Where indicated, multiple instances of the attribute may be defined.

| Attribute         | Multiple | Note |
|-------------------|----------|------|
| Name              | No       |      |
| Id                | No       |      |
| Type              | No       | (1)  |
| Checksum          | Yes      | (2)  |
| LicenseConcluded  | No       |      |
| LicenseDeclared   | No       | (3)  |
| LicenceInfoInFile | Yes      |      |
| LicenceComments   | No       |      |
| FilesAnalysis     | No       |      |
| CopyrightText     | No       |      |
| Comment           | No       |      |
| Originator        | No       |      |
| Supplier          | No       |      |
| Version           | No       |      |
| Homepage          | No       |      |
| Property          | Yes      | (4)  |
| DownloadLocation  | No       |      |
| Description       | No       |      |
| ExternalReference | Yes      | (5)  |
| Cpe               | No       |      |
| Purl              | No       | (6)  |
| Summary           | No       |      |
| SourceInfo        | No       |      |
| Filename          | No       |      |

**Note**

1. The set_type method is used to indicate the purpose of the package (e.g. Application, Library, Operating-System).

2. The set_checksum method takes two parameters, the checksum algorithm (e.g. SHA256) and the actual checksum value (as a string)

3. The set_licensedeclared method takes an optional second parameter which is the license name. In this case the first parameter, license, is assumed to be the license text rather than the license identity.

4. The set_property method takes two parameters which are the property name and value.

5. The set_externalreference method takes three parameters which are the category (SECURITY or PACKAGE_MANAGER), type (cpe22Type, cpe23Type or purl) and the element corresponding to the tyoe.

6. The set_cpe takes an optional second parameter which is the CPE type (default is cpeType23).

There is an additional setter method, **set_value**(_attribute, value_) which allows the setting of any attribute.

`set_value("language", "Rust")`

**_Getter Methods_**

get_package()
Returns the SBOMPackage object as a dictionary. The value of an attribute is returned as a string except where multiple instances of an attribute are allowed in which
case the value of the attribute is returned as a List.

get_name()
Returns the name of the SBOMPackage object or None if the 'name' attribute does not exist within the instance of the SBOMPackage object.

get_value(attribute)
Returns the value of the attribute. A default value is returned if the attribute does not exist within the instance of the SBOMPackage object.

get_purl()
Returns the PURL identifier as a string for the package or None if no PURL element is defined.

get_cpe()
Returns the CPE identifier as a string for the package or None if no CPE element is defined.

**_Utility Methods_**

initialise() Reinitialises a SBOMPackage Object. All data associated with the object is deleted.

**Example**

```python
>>> from lib4sbom.data.package import SBOMPackage
>>> sbom_packages = {}
>>> my_package = SBOMPackage()
>>> my_package.set_name("glibc")
>>> my_package.set_version("2.15")
>>> my_package.set_supplier("organisation","gnu")
>>> my_package.set_licensedeclared("GPL3")
>>> sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
>>> my_package.initialise()
>>> my_package.set_name("tomcat")
>>> my_package.set_version("9.0.46")
>>> my_package.set_supplier("organisation","apache")
>>> my_package.set_licensedeclared("Apache-2.0")
>>> sbom_packages[(my_package.get_name(), my_package.get_value('version'))] = my_package.get_package()
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_packages(sbom_packages)
```

### SBOMRelationship Object

_class_ **SBOMRelationship**()

This creates a simple SBOMRelationship object which is used to show the relationship between two items within an SBOM.
As there are multiple types of relationships, it is left to the application manipulating the
SBOMRelationship object to apply validation as appropriate to ensure the semantics of the relationship are correct.

**_Setter Methods_**

set_relationship (source, type, target)

_source_ and _target_ are the unique identifiers of the components for which the relationship is being defined.

_type_ is the type of relationship being defined.

**_Getter Methods_**

get_relationship()
Returns the SBOMRelationship object as a dictionary.

**Example**

```python
>>> from lib4sbom.data.relationship import SBOMRelationship
>>> sbom_relationships = []
>>> my_relationship = SBOMRelationship()
>>> my_relationship.set_relationship("Package-1","CONTAINS", "Package-2")
>>> sbom_relationships.append(my_relationship)
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_relationships(sbom_relationships)
```

### Vulnerability Object

_class_ **Vulnerability**(validation = None)

This creates a simple vulnerability object which is used to define the details of a vulnerability typically for a component
specified within an SBOM. As there are multiple ways of specifying the status of a vulnerability, it is left to the
application manipulating the Vulnerability object to apply validation as appropriate to ensure the semantics of the vulnerability are correct.

The following optional parameter can be specified:

_validation_ indicates that the status field is to be validated against the [OpenVEX](https://openvex.dev), [CycloneDX](https://www.cyclonedx.org) or [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) specifcaitions.

**NOTE** Vulnerability objects are only included in CyclonedDX SBOMs

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_release(). Each method takes a single parameter for the value. Multiple instances of the attribute are not allowed.


| Attribute         | Multiple | Note |
|-------------------|----------|------|
| Name              | No       |      |
| Id                | No       | (1)  |
| Release           | No       |      |
| Status            | No       | (2)  |
| Comment           | No       | (3)  |
| Description       | No       | (4)  |


**Note**

1. The set_id method is used to indicate the identity of the vulnerability e.g. CVE-2021-44228

2. The set_status is used to indicate the status of the vulnerability. Validation of the value of status may be optionally performed as determined by
the optional parameter _validation_ specified in the creation of the Vulnerability object. An invalid status is indicated by a value of None.

3. The set_comment method is used to provide additional information to support the status value e.g. a brief justification

4. The set_description method is used to describe the vulnerability.

There is an additional setter method, **set_value**(_attribute, value_) which allows the setting of any attribute.

`set_value("bom-ref", "rust@1.2.3")`

**_Getter Methods_**

get_vulnerability()
Returns the vulnerability object as a dictionary.

**Example**

```python
>>> from lib4sbom.data.vulnerability import Vulnerability
>>> vulnerabilities = []
>>> vulnerability = Vulnerability(validation="cyclonedx")
>>> vulnerability.set_id("CVE-2023-1235")
>>> vulnerability.set_name("rust")
>>> vulnerability.set_release("1.2.3")
>>> vulnerability.set_value("bom-ref", "rust@1.2.3")
>>> vulnerability.set_status("in_triage")
>>> vulnerabilities.append(vulnerability.get_vulnerability())
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_vulnerabilities(vulnerabilities)
```

### Services Object

_class_ **SBOMService**(validation = None)

This creates a simple software service object which is used to define the details of a software service.
As there are multiple ways of specifying a service, it is left to the
application manipulating the service object to apply validation as appropriate to ensure the semantics of the service are correct.

**NOTE** Services objects are only included in CyclonedDX SBOMs

**_Setter Methods_**

For the following attributes, a method **_set_attribute(value)_** is provided. Note that the attribute name is always in _lowercase_.
e.g. set_release(). Each method takes a single parameter for the value. Multiple instances of the attribute are not allowed.


| Attribute        | Multiple | Note |
|------------------|----------|------|
| Name             | No       |      |
| Id               | No       | (1)  |
| Version          | No       |      |
| Provider         | No       | (2)  |
| Endpoint         | Yes      |      |
| Data             | Yes      | (3)  |
| Property         | Yes      | (4)  |
| License          | Yes      |      |
| Exernalreference | Yes      | (5)  |
| Description      | No       |      |


**Note**

1. The set_id method is used to indicate the identity of the service. If this is not specified, an id will be automatically generated.

2. The set_provider is used to specify details of the service provider. There are multiple parameters which can be specified (name, url, contactname, email address and phone) at least one must be specified.

3. The set_data method is used to provide additional information to describe the data being exhanged. There are two mandatatory parameters flow type ("Inbound", "Outbound", "Bi-directional" or "Unknown") and classification, and two optional paramters name and description.

4. The set_property method takes two parameters which are the property name and value.

5. The set_externalreference method takes three parameters, the URL, the type of information being referenced and an optional comment.

There is an additional setter method, **set_value**(_attribute, value_) which allows the setting of any attribute.

`set_value("trustzone", "Data_DMZ")`

**_Getter Methods_**

get_service()
Returns the service object as a dictionary.

**Example**

```python
>>> from lib4sbom.data.service import SBOMService
>>> sbom_services = {}
>>> my_service=SBOMService()
>>> my_service.set_name("Microsoft 365")
>>> my_service.set_version("2022.04")
>>> my_service.set_provider(name="Microsoft Inc.", contact="Fred Flintstone", email="fred@micrsoft.com")
>>> my_service.set_description("Business productivity suite")
>>> my_service.set_value("authenticated",True)
>>> my_service.set_endpoint("www.microsoft.com")
>>> my_service.set_endpoint("www.microsoft.com/owa")
>>> my_service.set_data("Bi-directional","None",description="document")
>>> my_service.set_data("outbound","PII",name="User information")
>>> my_service.set_license("Apache-2.0")
>>> my_service.set_license("MIT")
>>> my_service.set_property("Data_Location","EU")
>>> my_service.set_externalreference("https://www.microsoft.com","Website", "Company website")
>>> sbom_services[(my_service.get_name(), my_service.get_value('version'))] = my_service.get_service()
>>> from lib4sbom.sbom import SBOM
>>> my_sbom = SBOM()
>>> my_sbom.add_services(sbom_services)
```

## Examples

A number of example scripts are included in the _examples_ subdirectory.
						
## Implementation Notes

The following design decisions have been made in processing the SBOM files:

1. It is assumed that the SBOM is valid and contains syntactically valid data.

2. In SPDX format, the tool assumes that the name of a package preceeds the version and license of the package.

3. In SPDX format, the current implementation does not currently handle multi-line elements.

4. When processing and validating licenses, the application will use a set of synonyms to attempt to map some license identifiers to the correct [SPDX License Identifiers](https://spdx.org/licenses/). However, the
user of the tool is reminded that they should assert the quality of any data which is provided by the tool particularly where the license identifier has been modified.

5. When parsing an SBOM with multiple instances of a component with the same name and version, only one instance of the comnponent is retained. If mulitple instances are
required to be preserved, consider ensuring that the component name is unique.

## Future Development

1. Support later versions of SPDX (3.0).

2. Enhance validation of SBOM data to check for all mandatory elements.

3. Implement Python typing across modules.

4. Migrate packaging infrastructure away from setup.py.

5. Utilise third-party SPDX and CycloneDX parsers and generators

6. Add further support for SPDX XML and RDF formats

7. Add generator for CycloneDX XML documents.

8. Implement test suite.

## License

Licensed under the Apache 2.0 Licence.

The tool uses a local copy of the [SPDX Licenses List](https://github.com/spdx/license-list-data) which is released under
[Creative Commons Attribution 3.0 (CC-BY-3.0)](http://creativecommons.org/licenses/by/3.0/).

This tool uses information sourced from the [Blue Oak Council's License List](https://blueoakcouncil.org/list) which is released under
[Creative Commons Attribution 1.0 (CC-BY-1.0)](https://creativecommons.org/licenses/by/1.0/).

## Limitations

This tool is meant to support software development. The usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

Parsing invalid SBOM files may lead to unpredictable results.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.
