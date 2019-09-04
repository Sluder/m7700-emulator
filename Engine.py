#!/usr/bin/python

from bitarray import bitarray
from Registers import Registers
from MemoryBlock import MemoryBlock

class Engine:
    def __init__(self, bin_start):
        self.r = Registers(bin_start)
        self.ram = MemoryBlock(0x1000, 0x14ff, 'RAM')

    def parse_instruction(self, inst_str):
        print('[log] Parsing \'{}\''.format(inst_str))

        instruction = inst_str.replace(',', '').split()
        # Call function related to opcode
        # try:
        getattr(self, instruction[0].upper())(instruction[1:])

        # except AttributeError:
        #     print('Unknown instruction \'{}\''.format(instruction[0]))
        # except Exception as e:
        #     print(e)

        print(self.r)

    def _format_bin(self, data):
        try:
            return bitarray(bin(data)[2:].zfill(16))
        except:
            return bitarray(bin(int(data, 16))[2:].zfill(16))

    def ADC(self, operands):
        """
        Addition with carry
        """
        reg_val = int(self.r.get_register(operands[0]).to01(), 2)
        ram_val = int(self.ram.load(operands[1]).to01(), 2)

        sum = ram_val + reg_val + int(self.r.get_flag('C'))

        sum_arr = self.r.set_register(operands[0], hex(sum & 0xff))

        self.r.checkZN(self._format_bin(sum))
        self.r.set_flag('C', sum > 0xff)

        if self.r.get_flag('m'):
            self.r.set_flag('V', ((~(reg_val ^ ram_val)) & (reg_val ^ sum) & 0x80))
        else:
            self.r.set_flag('V', ((~(reg_val ^ ram_val)) & (reg_val ^ sum) & 0x7fff))

    def AND(self, operands):
        """
        Logical AND
        """
        if self.r.get_flag('m') or operands[1].startswith('#'):
            self.r.set_register(operands[0], operands[1][1:] & self.r.get_register(operands[0]))
        else:
            self.r.set_register(operands[0], self.ram.load(operands[1]) & self.r.get_register(operands[0]))

        self.r.update_flags(['N', 'Z'], self.r.get_register(operands[0]))

    def ASL(self, operands):
        """
        Arithmetic shift left
        """
        pass

    def LDA(self, operands):
        """
        Load
        """
        if self.r.get_flag('m') or operands[1].startswith('#'):
            value = self.r.set_register(operands[0], self._format_bin(operands[1][1:]))
        else:
            value = self.r.set_register(operands[0], self.ram.load(operands[1]))

        self.r.checkZN(value)
