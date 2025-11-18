from elftools.elf.elffile import ELFFile
import argparse

targets = {
    "LLVMFuzzerTestOneInput": 0,
    "__sanitizer_cov_trace_pc_indir": 1,
    "__sanitizer_cov_trace_cmp8": 2,
    "__sanitizer_cov_trace_const_cmp8": 3,
    "__sanitizer_cov_trace_cmp4": 4,
    "__sanitizer_cov_trace_const_cmp4": 5,
    "__sanitizer_cov_trace_cmp2": 6,
    "__sanitizer_cov_trace_const_cmp2": 7,
    "__sanitizer_cov_trace_cmp1": 8,
    "__sanitizer_cov_trace_const_cmp1": 9,
    "__sanitizer_cov_trace_switch": 10,
    "__sanitizer_cov_trace_div4": 11,
    "__sanitizer_cov_trace_div8": 12,
    "__sanitizer_cov_trace_gep": 13,
    "__sanitizer_weak_hook_memcmp": 14,
    "__sanitizer_weak_hook_strncmp": 15,
    "__sanitizer_weak_hook_strcmp": 16,
    "__sanitizer_weak_hook_strncasecmp": 17,
    "__sanitizer_weak_hook_strcasecmp": 18,
    "__sanitizer_weak_hook_strstr": 19,
    "__sanitizer_weak_hook_strcasestr": 20,
    "__sanitizer_weak_hook_memmem": 21
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract symbol address from ELF file')
    parser.add_argument('elf', type=str, help='ELF file path')
    args = parser.parse_args()

    addrs = [0 for _ in range(len(targets))]
    with open(args.elf, 'rb') as f:
        elf = ELFFile(f)
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            if sym.name in targets:
                addrs[targets[sym.name]] = sym['st_value']
                
    print(len(targets))
    for idx, addr in enumerate(addrs):
        print(f'{idx},{addr:x}')
