#!/usr/bin/python

from bitarray import bitarray

class MemoryBlock:
    def __init__(self, from_addr, to_addr, name):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.name = name

        self.memory = {}
        for address in range(self.from_addr, self.to_addr):
            self.memory[hex(address)] = bitarray('0' * 8)

    def load(self, address):
        """
        Retreive data from memory
        """
        print('[{}] - Address \'{}\' read'.format(self.name, address))

        # Stuff bits for consistency
        return bitarray('0' * 8) + (self.memory[address])

    def store(self, address, data):
        """
        Store data into memory
        """
        print('[{}] - Address \'{}\' set {}'.format(self.name, address, data))

        self.memory[address] = bittarray(data)

    def __str__(self):
        str = ''

        for address in range(self.from_addr, self.to_addr):
            str += '{}\t{}\n'.format(hex(address), self.memory[hex(address)].tobytes().hex())

        return str
