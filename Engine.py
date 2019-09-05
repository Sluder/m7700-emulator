#!/usr/bin/python

from bitarray import bitarray
from Registers import Registers
from MemoryBlock import MemoryBlock

"""
todo:
- handle dp + ... operand
"""

class Engine:
    """
    Main code to emulate instructions
    """

    def __init__(self, bin_start):
        self.r = Registers(bin_start)
        self.ram = MemoryBlock(0x1000, 0x14ff, 'ram')

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

    def _format_bin(self, data):
        """
        Helper to convert numbers to binary format
        """
        try: # Already an int
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
        sum_arr = self.r.set_register(operands[0], self._format_bin(sum & 0xff))

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
            value = self._format_bin(operands[1][1:]) & self.r.get_register(operands[0])
            self.r.set_register(operands[0], value)
        else:
            value = self.ram.load(operands[1]) & self.r.get_register(operands[0])
            self.r.set_register(operands[0], value)

        self.r.checkZN(value)

    def ASL(self, operands):
        """
        Arithmetic shift left
        """
        pass

    def ASR(self, operands):
        """
        Arithmetic shift right
        """
        pass

    def CLB(self, operands):
        """
        Branch on carry clear
        """
        clear_bits = ~self._format_bin(operands[0][1:])
        memory = self.ram.load(operands[1])

        self.ram.store(operands[1], clear_bits & memory)

    def CLC(self, operands):
        """
        Clear carray flag
        """
        self.r.set_flag('C', 0)

    def CLI(self, operands):
        """
        Clear interrupt disable status
        """
        self.r.set_flag('I', 0)

    def CLM(self, operands):
        """
        Clear m flag
        """
        self.r.set_flag('m', 0)

    def CLM(self, operands):
        """
        Clear processor status
        """
        self.r.set_flag('m', 0)

    def CLV(self, operands):
        """
        Clear overflow flag
        """
        self.r.set_flag('V', 0)

    def CMP(self, operands):
        """
        Compare
        """
        if operands[1].startswith('#'):
            reg_val = int(self.r.get_register(operands[0]).to01(), 2)
            op_val = int(self._format_bin(operands[1][1:]).to01(), 2)
            value = reg_val - op_val
        else:
            reg_val = int(self.r.get_register(operands[0]).to01(), 2)
            ram_val = int(self.ram.load(operands[1]).to01(), 2)
            value = reg_val - ram_val

        self.r.checkZN(value)
        self.r.set_flag('C', value > 0)

    def LDA(self, operands):
        """
        Load
        """
        if operands[1].startswith('#'):
            value = self.r.set_register(operands[0], self._format_bin(operands[1][1:]))
        else:
            value = self.r.get_register(operands[0], self.ram.load(operands[1]))

        self.r.checkZN(int(value.to01(), 2))
