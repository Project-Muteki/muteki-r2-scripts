#!/usr/bin/env python3
# Read syscall shim DLLs and output the mapping to stdout.

import r2pipe
import sys
import json

def get_current_vaddr(r):
    return int(r.cmd('s').strip(), 0)

def read_syscall_shim(dll_path):
    r = r2pipe.open(dll_path)
    exports = r.cmdj('iEj')
    syscalls = {}
    for exp in exports:
        if exp['bind'] != 'GLOBAL' or exp['type'] != 'FUNC':
            raise RuntimeError(f'Unexpected entry {exp} in export table (not a global function).')

        shim_offset = exp['vaddr']
        syscall_name = exp['name']

        svc_offset = shim_offset + 8 # skip preamble

        instr = r.cmdj(f'pij 1 @ {svc_offset}')[0]
        if instr['type'] != 'swi':
            raise RuntimeError(f'Instruction at {hex(svc_offset)} is not SVC type.')

        syscalls[hex(instr['val'])] = syscall_name
    r.quit()
    return syscalls

if __name__ == '__main__':
    syscalls = read_syscall_shim(sys.argv[1])
    print(json.dumps(syscalls, sort_keys=True, indent=4))
