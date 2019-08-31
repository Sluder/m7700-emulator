#!/usr/bin/python

import binascii
from Engine import Engine

def print_code():
    address = 0

    with open('722531-1996-UK-SVX-EG33.bin', 'r+b') as f:
        while True:
            bytes = binascii.hexlify(f.read(16))

            if not bytes:
                break
            bytes = ' '.join([bytes[i:i + 2] for i in range(0, len(bytes), 2)])
            print("{} {}".format('0x' + hex(address)[2:].zfill(4), bytes))

            address += 16
            f.seek(address)

if __name__ == '__main__':
    engine = Engine(0x9000)

    engine.parse_instruction('lda bl, #0x90')
