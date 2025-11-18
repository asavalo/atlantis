from elftools.elf.elffile import ELFFile
import argparse

targets = {
    "runtime.memequal":                             0,
    "internal/bytealg.Compare":                     1,
    "runtime.cmpstring":                            2,
    "internal/bytealg.Count.abi0":                  3,
    "internal/bytealg.CountString.abi0":            4,
    "internal/bytealg.IndexByte.abi0":              5,
    "internal/bytealg.IndexByteString.abi0":        6,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract symbol address from ELF file')
    parser.add_argument('elf', type=str, help='ELF file path')
    parser.add_argument('output', type=str, nargs='?', help='Output file path', default='')
    args = parser.parse_args()

    addrs = [0 for _ in range(len(targets))]
    with open(args.elf, 'rb') as f:
        elf = ELFFile(f)
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            if sym.name in targets:
                addrs[targets[sym.name]] = sym['st_value']
    
    output = ''
    output += f'{len(targets)}\n'
    for idx, addr in enumerate(addrs):
        output += f'{idx},{addr:x}\n'
    
    try:
        with open(args.output, 'w') as f:
            f.write(output)
    except:
        print(output)
