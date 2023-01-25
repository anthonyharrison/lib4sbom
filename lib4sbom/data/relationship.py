# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMRelationship:
    def __init__(self):
        self.relationship = {}

    def initialise(self):
        self.relationship = {}

    def set_relationship(self, source, type, target):
        self.relationship["source"] = source
        self.relationship["type"] = type.strip()
        self.relationship["target"] = target

    def set_relationship_id(self, id_s, id_t):
        self.relationship["source_id"] = id_s
        self.relationship["target_id"] = id_t

    def get_relationship(self):
        return self.relationship

    def get_source(self):
        return self.relationship["source"]

    def get_type(self):
        return self.relationship["type"]

    def get_target(self):
        return self.relationship["target"]

    def show_relationship(self):
        for key in self.relationship:
            print(f"{key}    : {self.relationship[key]}")

    def debug_relationship(self):
        print("OUTPUT:", self.relationship)
