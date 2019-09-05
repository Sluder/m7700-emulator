#!/usr/bin/python

from bitarray import bitarray

class MemoryBlock:
    """
    Segments of memory blocks
    - Typically 8-bit data containers, but padded to 16-bits for consistency
    """

    def __init__(self, from_addr, to_addr, name):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.name = name

        # Fill memory with zeros
        self.memory = {}
        for address in range(self.from_addr, self.to_addr):
            self.memory[hex(address)] = bitarray('1' * 8)

    def load(self, address):
        """
        Retreive data from memory
        :param address: Hex str
        """
        print('[{}] - Address \'{}\' read'.format(self.name, address))

        return bitarray('0' * 8) + (self.memory[address])

    def store(self, address, data):
        """
        Store data into memory
        :param address: Hex str
        :param data: BitArray
        """
        print('[{}] - Address \'{}\' set {}'.format(self.name, address, '0x' + data.tobytes().hex()))

        self.memory[address] = data

    def __str__(self):
        str = ''

        for address in range(self.from_addr, self.to_addr):
            str += '{}\t{}\n'.format(hex(address), self.memory[hex(address)].tobytes().hex())

        return str
