#!/usr/bin/env python3
#
# Besta syscall tagger.
#
# Runs via #!pipe inside the memory dump loaded by the loader script.
#
# Assumes loc.__syscall_table_sdk and loc.__syscall_table_krnl flags are
# previously defined by the loader script.
#

import json
import sys

import r2pipe

SYSCALL_TABLE_FLAG_PREFIX = 'loc.__syscall_table_'
SYSCALL_TABLE_LOC = {
    1: 'sdk',
    2: 'krnl'
}

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        syscalls = json.load(f)

    r = r2pipe.open()
    print('fs+functions')
    for num_hex, name in syscalls.items():
        num = int(num_hex, 0)

        syscall_type = SYSCALL_TABLE_LOC[num >> 16]
        syscall_table = SYSCALL_TABLE_FLAG_PREFIX + syscall_type
        syscall_handler_entry_offset = f'{syscall_table}+{(num & 0xffff) * 4}'
        syscall_handler_func_offset = int(r.cmd(f'pv4 @ {syscall_handler_entry_offset}').strip(), 0)
        print(f'f loc.__syscall_{syscall_type}_{name} @ {syscall_handler_entry_offset}')
        print(f'f fcn.{syscall_type}_{name} @ {hex(syscall_handler_func_offset)}')

    print('fs-')
    r.quit()
