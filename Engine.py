#!/usr/bin/python

from Registers import Registers
from MemoryBlock import MemoryBlock

class Engine:
    def __init__(self, bin_start):
        self.registers = Registers(bin_start)
        self.ram = MemoryBlock(0x1000, 0x14ff)

    def parse_instruction(self, inst_str):
        instruction = inst_str.replace(',', '').split()

        # Call function related to opcode
        # try:
        getattr(self, instruction[0])(instruction[1:])

        # except AttributeError:
        #     print('Unknown instruction \'{}\''.format(instruction[0]))
        # except Exception as e:
        #     print(e)

        print(self.registers)

    def update_flags(self, last_value):
        self.registers.set_flag('Z', 0)
        self.registers.set_flag('N', 0)

        if last_value == 0:
            self.registers.set_flag('Z', 1)
        else:
            if self.registers.get_flag('m') and bin(int(last_value, 16))[2:].zfill(8)[7]:
                self.registers.set_flag('N', 1)

            elif bin(int(last_value, 16))[2:].zfill(16)[15]:
                self.registers.set_flag('N', 1)

    def lda(self, operands):
        destination = operands[0]

        if self.registers.get_flag('m') or operands[1].startswith('#'):
            self.registers.set_register('a', operands[1][1:])
        else:
            self.registers.set_register('a', self.ram.load(operands[1]))

        self.update_flags(self.registers.get_register('a'))
