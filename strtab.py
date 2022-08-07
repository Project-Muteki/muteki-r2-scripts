#!/usr/bin/env python3

import contextlib
import sys

import r2pipe

def resolve_r2_ref(r: r2pipe.open, ref: str) -> int:
    return int(r.cmdj(f'?j {ref}')['uint64'])

def ptr_deref(r: r2pipe.open, ptr: int | str) -> int:
    return r.cmdj(f'pv4j @ {ptr}')[0]['value']

def read_utf16_str(r: r2pipe.open, ptr: int | str) -> str:
    result = bytearray()
    while True:
        cu = r.cmdj(f'pv2j @ {ptr}')[0]['value']
        if cu == 0:
            break
        result.extend(cu.to_bytes(2, 'little'))
        ptr += 2
    return result.decode('utf-16le')

def query_strtab(r: r2pipe.open, idx: int, lang: int) -> str | None:
    strtab_base = resolve_r2_ref(r, 'loc.strtab_base')
    print('strtab_base =', hex(strtab_base))
    if idx < 0x4000:
        print('BANK 1')
        lang_offset = lang if lang < 4 else 0
        idx_base = ptr_deref(r, strtab_base + lang_offset * 4 + 0xc)
    else:
        print('BANK 2')
        idx_base = ptr_deref(r, strtab_base + (0x30 if lang == 1 else 0x34))

    print('idx_base =', hex(idx_base))
    if idx_base != 0 and idx < ptr_deref(r, idx_base):
        str_offset = ptr_deref(r, idx_base + 4 * (idx + 1))
        print('str_offset =', hex(str_offset))
        return read_utf16_str(r, idx_base + str_offset)

    return None

def iterate_index(r: r2pipe.open, ptr: str, lang: int):
    offset = resolve_r2_ref(r, ptr)
    print(ptr, '->', hex(offset))
    while True:
        result = r.cmdj(f'pv4j 2 @ {offset}')
        key = result[0]['value']
        validx = result[1]['value']
        if key == 0 and validx == 0:
            break
        print(hex(key), hex(validx))
        yield key, query_strtab(r, validx, lang)
        offset += 8

if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) >= 2 else None
    r = r2pipe.open()
    if action == 'iterate-index':
        for key, str_ in iterate_index(r, sys.argv[2], int(sys.argv[3], 0)):
            print(f'{key:#06x}: {str_}')
    elif action == 'query':
        print(query_strtab(r, int(sys.argv[2], 0), int(sys.argv[3], 0)))
    else:
        if action is not None:
            print('Error: invalid action', action)
        print(f'Usage: #!pipe python {sys.argv[0]} action ref langid')
