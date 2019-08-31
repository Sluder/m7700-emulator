#!/usr/bin/python

class MemoryBlock:
    def __init__(self, from_addr, to_addr):
        self.from_addr = hex(from_addr)
        self.to_addr = hex(to_addr)

        self.memory = [0] * (int(to_addr) - int(from_addr))

    def load(self, address):
        """
        Retreive data from memory
        """
        return self.memory[int(address, 16) - int(self.from_addr, 16)]

    def store(self, address, data):
        """
        Store data into memory
        """
        self.memory[int(address) - int(self.from_addr)] = hex(data)
