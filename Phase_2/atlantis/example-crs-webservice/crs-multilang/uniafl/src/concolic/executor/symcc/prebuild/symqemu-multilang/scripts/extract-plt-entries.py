from pwn import *
import argparse

context.arch = 'amd64'
context.log_level = 'CRITICAL'

targets = {
    "strncmp":      0,
    "memcmp":       1,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract plt entry address from ELF file')
    parser.add_argument('elf', type=str, help='ELF file path')
    parser.add_argument('output', type=str, nargs='?', help='Output file path', default='')
    args = parser.parse_args()

    addrs = [0 for _ in range(len(targets))]
    elf = ELF(args.elf)
    for target in targets:
        if target in elf.plt:
            addr = elf.plt[target]
            if elf.read(addr - 4, 4) == asm('endbr64'):
                addr -= 4
            addrs[targets[target]] = addr
    
    output = ''
    output += f'{len(targets)}\n'
    for idx, addr in enumerate(addrs):
        output += f'{idx},{addr:x}\n'

    try:
        with open(args.output, 'w') as f:
            f.write(output)
    except:
        print(output)
