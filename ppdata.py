#!/usr/bin/env python3
# Read and print SEH/R (SEH on RISC) .pdata section.

import r2pipe
from collections import namedtuple
import sys

ARMPDataEntry = namedtuple('ARMPDataEntry', ['addr', 'prolog_insts', 'function_insts', 'thumb', 'has_handler'])

if __name__ == '__main__':
    r = r2pipe.open(sys.argv[1])

    binary_sections = r.cmdj('iSj')

    pdatas = tuple(filter(lambda sec: sec['name'] == '.pdata', binary_sections))
    if len(pdatas) > 1:
        print('WARNING: Multiple .pdata found. Use the first one.')
    elif len(pdatas) == 0:
        print('No .pdata found.')
        sys.exit(1)
    pdata = pdatas[0]
    pdata_end_offset = pdata['size'] + pdata['vaddr']

    r.cmd('s section..pdata')
    while True:
        current_offset = int(r.cmd('s').strip(), 0)
        if current_offset >= pdata_end_offset:
            print('Section boundary reached.')
            break
        addr = int(r.cmd(f'pv4').strip(), 0)
        if addr == 0:
            print('End of record.')
            break
        offset = int(r.cmd('pv4').strip(), 0)
        flags = int(r.cmd('pv4 @ +4').strip(), 0)
        prolog_insts = flags & 0xff
        function_insts = (flags >> 8) & ((1 << 22) - 1)
        thumb = not bool(flags & (1 << 30))
        has_handler = bool(flags & (1 << 31))
        print(f'offset=0x{offset:x}, prolog_insts={prolog_insts}, function_insts={function_insts}, thumb={thumb}, has_handler={has_handler}')
        r.cmd('s +8')

    r.quit()
