#!/usr/bin/python

class Registers:
    def __init__(self, pc=0x0):
        self.reset(pc)

    def reset(self, pc):
        self.pc = hex(pc)

        self.a = 0 # Accumulator
        self.b = 0 # 2nd Accumulator
        self.x = 0 # Index
        self.y = 0 # 2nd Index
        self.s = 0 # Stack pointer

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

    def _to_bin(self, data):
        """
        Normalizes data to binary
        """
        return bin(int(str(data), 16))[2:].zfill(16)

    def _get_lower(self, register_name):
        """
        Gets lower 8 bits of a register
        """
        value = self._to_bin(getattr(self, register_name))[8:]

        return '0x' + hex(int(value, 2))[2:].zfill(2)

    def _get_higher(self, register_name):
        """
        Gets higher 8 bits of a register
        """
        value = self._to_bin(getattr(self, register_name))[:8]

        return '0x' + hex(int(value, 2))[2:].zfill(2)

    def get_register(self, register_name):
        """
        Retreive data from a register
        """
        if register_name in ['al', 'bl', 'xl', 'yl']:
            return self._get_lower(register_name)

        elif register_name in ['ah', 'bh', 'xh', 'yh']:
            return self._get_higher(register_name)

        return '0x' + hex(int(self._to_bin(getattr(self, register_name)), 2))[2:].zfill(4)

    def set_register(self, register_name, value):
        """
        Set new data for a register
        """
        setattr(self, register_name, value)

    def get_flag(self, flag):
        return bool(self.flags[flag])

    def set_flag(self, flag, value):
        self.flags[flag] = bool(value)

    def __str__(self):
        return '\n'.join((
            'PC: {}'.format(self.get_register('pc')),
            'A: {} | AL: {} | AH: {}'.format(self.get_register('a'), self._get_lower('a'), self._get_higher('a')),
            'B: {} | BL: {} | BH: {}'.format(self.get_register('b'), self._get_lower('b'), self._get_higher('b')),
            'X: {} | XL: {} | XH: {}'.format(self.get_register('x'), self._get_lower('x'), self._get_higher('x')),
            'Y: {} | YL: {} | YH: {}'.format(self.get_register('y'), self._get_lower('y'), self._get_higher('y'))
        ))
