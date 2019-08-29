#!/usr/bin/python

from Registers import Registers

def setup_registors(start_addr):
    return Registers(start_addr)

if __name__ == '__main__':
    registors =  setup_registors(0x9000)
