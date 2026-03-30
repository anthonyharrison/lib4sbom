# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMAnnotation:
    def __init__(self):
        self.annotation = []
        self.annatotor = {}

    def initialise(self):
        self.annotation = {}

    def set_annatator(self, annotation_type, name, email):
        if annotation_type in ["organization", "individual"]:
            self.annatotor = {
                "annotator_type": annotation_type,
                "name": name,
                "email": email,
            }

    def add(self, subject, text):
        annotation_entry = {
            "annotator": self.annatotor,
            "subject": [subject],
            "text": text,
        }
        if len(self.annotation) > 0:
            self.annotation.append(annotation_entry)
        else:
            self.annotation = annotation_entry

    def get_annotation(self):
        return self.annotation

    def debug_annotation(self):
        print("OUTPUT:", self.annotation)

    def show_annotation(self):
        for key in self.annotation:
            print(f"{key}    : {self.annotation[key]}")
