# Finds the root of memchunk chain with a known memchunk.
# Usually this only needs to be ran once per machine per OS version.

import sys

import r2pipe

if __name__ == '__main__':
    r = r2pipe.open()
    # resolve tail
    tail = int(r.cmdj(f'?j {sys.argv[1]}')['uint32'])

    while True:
        prev = r.cmdj(f'pv4j @ {tail}')[0]['value']
        print(hex(tail), '->', hex(prev))
        if prev != 0:
            tail = prev
        else:
            print('Is this the end?')
            break
