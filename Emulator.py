#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *
from keystone import *

START_ADDR = 0x1000

if __name__ == '__main__':
    hex_arr = []

    for i in (Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm("add r0,r1,r2", 0))[0]:
        hex_arr.append(i)

    hex_dump = bytes(hex_arr)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(START_ADDR, 2 * 1024 * 1024)

    uc.mem_write(START_ADDR, hex_dump)
    uc.reg_write(UC_ARM_REG_R0, 0x1111)
    uc.reg_write(UC_ARM_REG_R1, 0x1111)
    uc.reg_write(UC_ARM_REG_R2, 0x1111)

    uc.emu_start(START_ADDR | 1, START_ADDR + len(hex_dump))

    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)

    print("R0 {}".format(r0))
    print("R1 {}".format(r1))
    print("R2 {}".format(r2))
