#!/usr/bin/env python3

import struct

import r2pipe

def custom_psw(r, offset):
    current_offset = offset
    while True:
        raw = bytearray(r.cmdj(f'pxj 512 @ {current_offset}'))
        unpacked = struct.unpack('<256H', raw)
        non0 = []
        found_0 = False
        for val in unpacked:
            if val == 0:
                found_0 = True
                break
            else:
                non0.append(val)
        if found_0:
            break
        current_offset += 512
    return struct.pack(f'<{len(non0)}H', *non0).decode('utf-16')


def dump_loaded_app_metadata(r, offset):
    load_address_types = {1: 'Direct', 2: 'Indirect'}
    app_executable_types = {0: 'Registered', 1: 'Independent'}
    trailing_0 = '\x00'

    if offset == 0:
        return
    loaded_app = bytearray(r.cmdj(f'pxj 152 @ {offset}'))
    assert len(loaded_app) == 152, 'Loaded app metadata size mismatch.'

    unpacked = struct.unpack('<80sI2i2I2H2I10I', loaded_app)

    load_address_type_enum = load_address_types.get(unpacked[6], 'Unknown')
    app_executable_type_enum = app_executable_types.get(unpacked[7], 'Unknown')
    app_name = custom_psw(r, unpacked[9]) # r.cmdj(f'pswj @ {unpacked[9]}')

    print(f'  DOS Path: {unpacked[0].decode("ascii").rstrip(trailing_0)}')
    print(f'  Slot Number (?): {unpacked[1]:#010x}')
    print(f'  Load RefCnt.: {unpacked[2]}')
    print(f'  TSR RefCnt.: {unpacked[3]}')
    print(f'  Image address: {unpacked[4]:#010x}')
    print(f'  unk96: {unpacked[5]:#010x}')
    print(f'  Load address type: {load_address_type_enum} ({unpacked[6]:#06x})')
    print(f'  App executable type: {app_executable_type_enum} ({unpacked[7]:#06x})')
    print(f'  unk104: {unpacked[8]:#010x}')
    print(f'  Full Path: {app_name}')
    for idx, unk_val in enumerate(unpacked[10:]):
        unk_offset = 112 + 4 * idx
        print(f'  unk{unk_offset}: {unk_val:#010x}')
        if unk_val != 0:
            ...

if __name__ == '__main__':
    r = r2pipe.open()
    # pv4j does not work. Workaround by reading raw bytes and processing on client side.
    offsets = struct.unpack('<16I', bytearray(r.cmdj('pxj 64 @ loc.__loaded_apps')))
    for idx, offset in enumerate(offsets):
        print(f'Slot #{idx}')
        dump_loaded_app_metadata(r, offset)
