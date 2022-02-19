# Lists all memchunks presented in the dump
# #!pipe python path/to/list_memchunk.py > private/memchunks.r2i
from typing import TypedDict

import functools

import r2pipe

class ParsedMemchunkMetadata(TypedDict):
    offset: int
    prev_chunk: int
    next_chunk: int
    size: int
    tail: bool


def read_memchunk(r: r2pipe.open, offset: int) -> ParsedMemchunkMetadata:
    prev_chunk = r.cmdj(f'pv4j @ {offset}')[0]['value']
    next_tail = r.cmdj(f'pv4j @ {offset+4}')[0]['value']
    tail = (next_tail & 1) == 0
    next_chunk = next_tail & (~1)

    return {
        'offset': offset,
        'prev_chunk': prev_chunk,
        'next_chunk': next_chunk,
        'size': next_chunk - offset,
        'tail': tail,
    }

if __name__ == '__main__':
    r = r2pipe.open()
    heap_base = int(r.cmdj('?j section.sdram.heapbase')['uint32'])
    offset = heap_base
    expected_prev_offset = 0
    total_alloc = 0

    print('fs+ memchunk')
    while True:
        chunk = read_memchunk(r, offset)
        total_alloc += chunk['size']
        print('#', hex(offset), '->', hex(chunk['next_chunk']))
        print(f'f mch.{chunk["offset"]:08x}', chunk['size'], '@', hex(chunk['offset']))
        if expected_prev_offset != chunk['prev_chunk']:
            print(f'# WARNING: Memchunk has inconsistent link (previous chunk located @ {hex(expected_prev_offset)}, but current chunk links back to {hex(chunk["prev_chunk"])})')
        if chunk['tail']:
            print(f'# {total_alloc:,} bytes allocated.')
            break
        offset = chunk['next_chunk']
        expected_prev_offset = chunk['offset']
    print('fs- memchunk')
