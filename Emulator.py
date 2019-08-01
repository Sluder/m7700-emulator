#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *
from keystone import *

START_ADDR = 0x0000

mem_ranges = {
    'IO' : {'begin': 0x0000, 'end': 0x5000}
}

def hook_mem_access(uc, access, address, size, value, user_data):
    # Check if we accessed from a mem range
    # for type, ranges in mem_ranges.items():
    #     if hex(address) >= hex(ranges['begin']) and hex(address) <= hex(ranges['end']):
    #         if access == UC_MEM_WRITE:
    #             print('Wrote to {} {}'.format(type, hex(address)))
    #         else:
    #             print('Loaded from {} {}'.format(type, hex(address)))
    print('Accessed {}'.format(hex(address)))

if __name__ == '__main__':
    hex_arr = []

    # TODO: load asm from file
    for i in (Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm("ldr r0, 0x1000", 0))[0]:
        hex_arr.append(i)

    hex_dump = bytes(hex_arr)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(START_ADDR, 4 * 1024 * 1024)
    uc.mem_write(START_ADDR, hex_dump)

    # Hooks
    # uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_access, None, 0x0000, 0x5000)

    uc.mem_write(0x4, b'0x1234')
    uc.reg_write(UC_ARM_REG_R0, 0x1111)

    uc.emu_start(START_ADDR | 1, START_ADDR + len(hex_dump))

    print("R0 - {}".format(uc.reg_read(UC_ARM_REG_R0)))
