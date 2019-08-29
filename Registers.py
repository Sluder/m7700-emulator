#!/usr/bin/python

class Registers:
    def __init__(self, pc=0x0):
        self.reset(pc)

    def reset(self, pc):
        self.pc = pc

        self.ax = [0] * 16
        self.bx = [0] * 16

        self.flags = {
            'N' : 0, # Negative
            'V' : 0, # Overflow
            'm' : 0, # Date length
            'x' : 0, # Index register length
            'D' : 0, # Disable mode
            'I' : 0, # Interrupt disable
            'Z' : 0, # Zero
            'C' : 0  # Carry
        }

        def read(register):
            pass
