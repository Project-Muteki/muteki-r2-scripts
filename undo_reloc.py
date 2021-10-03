#!/usr/bin/env python3
# TODO this needs to be rewritten based on .reloc table.

import r2pipe
import sys
import re
import itertools

LDR_MATCH_PATTERN = re.compile(r'^ldr (?:r\d+|ip|lr), \[pc(?:, (-?(?:0x[a-f0-9]+|[0-9]+)))?\]$')

if __name__ == '__main__':
    r = r2pipe.open(sys.argv[1])
    real_load_addr = int(sys.argv[2], 0)

    binary_info = r.cmdj('ij')
    bin_load_addr = binary_info['bin']['baddr']

    load_addr_offset = real_load_addr - bin_load_addr

    binary_sections = r.cmdj('iSj')
    max_vaddr = bin_load_addr
    bin_end_addr = bin_load_addr
    for sec in binary_sections:
        if sec['vaddr'] > max_vaddr:
            max_vaddr = sec['vaddr']
            bin_end_addr = sec['vaddr'] + sec['vsize']

    real_end_addr = load_addr_offset + bin_end_addr

    print(f'# File "{binary_info["core"]["file"]}" is mapped at vaddr 0x{bin_load_addr:08x}-0x{bin_end_addr:08x} (paddr 0x{real_load_addr:08x}-0x{real_end_addr:08x})')

    # Fix lea (indirect) references in .text
    # Multiple indirect references are not supported. Can it even be supported? What did the Besta ld do to achieve this in the first place?
    print(f'# lea fixes')
    potential_leas = r.cmdj('/ad/j ldr r\d+, \[pc')
    potential_leas_syscall_trampoline = r.cmdj('/ad/j ldr ip, \[pc')
    potential_leas_lr = r.cmdj('/ad/j ldr lr, \[pc')
    
    for lea in itertools.chain(potential_leas, potential_leas_syscall_trampoline, potential_leas_lr):
        m = LDR_MATCH_PATTERN.match(lea['code'])
        if m is not None:
            pcrel = int(m.group(1), 0) if m.group(1) is not None else 0
            address_offset = lea['offset'] + pcrel + 8
            value = int(r.cmd(f'pv4 @ {address_offset}').strip(), 0)
            
            #print(hex(lea['offset']), hex(value))
            if real_load_addr <= value < real_end_addr:
                print('wv4', hex(value - load_addr_offset), '@', hex(address_offset))
            else:
                print('# Instruction', lea, f'does not load a value that points to the inside of this executable ({hex(value)}). Ignoring.')
        else:
            print(f'# Unrecognized ldr instruction {lea}')

    # Fix pdata table
    print(f'# .pdata fixes')
    pdatas = tuple(filter(lambda sec: sec['name'] == '.pdata', binary_sections))
    if len(pdatas) > 1:
        print('# Multiple .pdata found. Use the first one.')
    pdata = pdatas[0]
    pdata_end_offset = pdata['size'] + pdata['vaddr']

    r.cmd('s section..pdata')
    while True:
        current_offset = int(r.cmd('s').strip(), 0)
        if current_offset >= pdata_end_offset:
            print('# Section boundary reached.')
            break
        addr = int(r.cmd(f'pv4').strip(), 0)
        if addr == 0:
            print('# End of record.')
            break
        elif real_load_addr <= addr < real_end_addr:
            print('wv4', hex(addr - load_addr_offset), '@', hex(current_offset))
        else:
            print('# Entry', hex(addr), '@', hex(current_offset), 'is not within the loaded binary.')
        r.cmd('s +8')

    # TODO clean up reloc table in .data
    r.quit()
