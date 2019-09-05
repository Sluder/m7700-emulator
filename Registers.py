#!/usr/bin/python

import sys
from bitarray import bitarray

class Registers:
    """
    Holds all M7700 16-bit registers
    - Partial reg's like 'ax' can be used as higher & lower registers (i.e. ah, al)
    """

    def __init__(self, pc=0x0):
        self.reset(pc)

    def reset(self, pc):
        self.pc = bitarray(bin(pc)[2:])

        self.ax = bitarray('0' * 16) # Accumulator
        self.bx = bitarray('0' * 16) # 2nd Accumulator
        self.xx = bitarray('0' * 16) # Index
        self.yx = bitarray('0' * 16) # 2nd Index
        self.s = bitarray('0' * 16)  # Stack pointer

        self.ps = {
            'C' : 0, # Carry
            'Z' : 0, # Zero
            'I' : 0, # Interrupt disable
            'D' : 0, # Disable mode
            'x' : 0, # Index register length
            'm' : 0, # Date length
            'V' : 0, # Overflow
            'N' : 0, # Negative
        }

    def get_register(self, register_name):
        """
        Retreive data from a register
        :param register_name: e.g. 'ax' or 'al'
        """
        # Grab specfic bits of a register. Add 'x' to get correct register
        if register_name in ['al', 'bl', 'xl', 'yl']:
            return bitarray(getattr(self, register_name[:1] + 'x'))[8:]

        elif register_name in ['ah', 'bh', 'xh', 'yh']:
            return bitarray(getattr(self, register_name[:1] + 'x'))[:8]

        return bitarray(getattr(self, register_name))

    def set_register(self, register_name, value):
        """
        Set new data for a register
        :param register_name: e.g. 'ax' or 'al'
        :param value: BitArray value (16 bits)
        :returns: BitArray of value (16 bits)
        """
        parent_reg = register_name[:1] + 'x'
        parent_val = getattr(self, parent_reg)

        # Reformat value for bitstuffing
        if register_name in ['al', 'bl', 'xl', 'yl']:
            value = parent_val[:8] + value[8:]
            setattr(self, parent_reg, value)

        elif register_name in ['ah', 'bh', 'xh', 'yh']:
            value = value[8:] + parent_val[8:]
            setattr(self, parent_reg, value)

        else:
            setattr(self, parent_reg, value)

        print('[reg] - Register \'{}\' set {}'.format(register_name, '0x' + value.tobytes().hex()))

        return value

    def get_flag(self, flag):
        """
        Gets current value of a flag
        :param flag: Character of flag to retrieve
        """
        return bool(self.ps[flag])

    def set_flag(self, flag_name, value):
        """
        Set new value for flag
        :param flag_name: e.g. 'N' or 'm'
        :param value: 1 or 0
        """
        self.ps[flag_name] = int(value)

    def checkZN(self, last_value):
        """
        Sets zero & negative flags if applicable
        :parm last_value: Last calculated value (Expects int)
        """
        self.set_flag('Z', last_value == 0)
        self.set_flag('N', last_value < 0)

    def __str__(self):
        return '\n'.join((
            '\nPC: 0x{}'.format(self.get_register('pc').tobytes().hex()),
            'A: 0x{} | AH: 0x{} | AL: 0x{}'.format(self.get_register('ax').tobytes().hex(), self.get_register('ah').tobytes().hex(), self.get_register('al').tobytes().hex()),
            'B: 0x{} | BH: 0x{} | BL: 0x{}'.format(self.get_register('bx').tobytes().hex(), self.get_register('bh').tobytes().hex(), self.get_register('bl').tobytes().hex()),
            'X: 0x{} | XH: 0x{} | XL: 0x{}'.format(self.get_register('xx').tobytes().hex(), self.get_register('xh').tobytes().hex(), self.get_register('xl').tobytes().hex()),
            'Y: 0x{} | YH: 0x{} | YL: 0x{}'.format(self.get_register('yx').tobytes().hex(), self.get_register('yh').tobytes().hex(), self.get_register('yl').tobytes().hex()),
            ' | '.join('%s: %s' % (flag, value) for (flag, value) in self.ps.items())
        ))
