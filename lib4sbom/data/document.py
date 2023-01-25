# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMDocument:
    def __init__(self):
        self.document = {}

    def initialise(self):
        self.document = {}

    def set_name(self, name):
        self.document["name"] = name

    def set_id(self, id):
        self.document["id"] = id

    def set_version(self, version):
        self.document["version"] = version

    def set_type(self, type):
        self.document["type"] = type

    def set_datalicense(self, license):
        self.document["datalicense"] = license

    def set_value(self, key, value):
        self.document[key] = value

    def get_document(self):
        return self.document

    def debug_document(self):
        print("OUTPUT:", self.document)

    def show_document(self):
        for key in self.document:
            print(f"{key}    : {self.document[key]}")

    def copy_document(self, document):
        for key in document:
            self.set_value(key, document[key])

    def get_name(self):
        return self.get_value("name", default="NOT DEFINED")

    def get_version(self):
        return self.get_value("version", default="MISSING")

    def get_type(self):
        return self.get_value("type")

    def get_datalicense(self):
        return self.get_value("datalicense")

    def get_value(self, attribute, default=None):
        return self.document.get(attribute, default)
