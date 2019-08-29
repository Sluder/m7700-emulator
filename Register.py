#!/usr/bin/python

class Register:
    def __init__(self, name, default_value=0):
        self.name = name
        self.data = default_value

    def load(self, value):
        self.data = value
