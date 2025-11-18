use crate::common::Error;
use object::{File as ElfFile, Object, ObjectSymbol};
use std::io::Read;
use std::{fs::File, path::PathBuf};

pub fn get_libfuzzer_symbols_string(elf_path: &PathBuf) -> Result<String, Error> {
    let targets = [
        "LLVMFuzzerTestOneInput",
        "__sanitizer_cov_trace_pc_indir",
        "__sanitizer_cov_trace_cmp8",
        "__sanitizer_cov_trace_const_cmp8",
        "__sanitizer_cov_trace_cmp4",
        "__sanitizer_cov_trace_const_cmp4",
        "__sanitizer_cov_trace_cmp2",
        "__sanitizer_cov_trace_const_cmp2",
        "__sanitizer_cov_trace_cmp1",
        "__sanitizer_cov_trace_const_cmp1",
        "__sanitizer_cov_trace_switch",
        "__sanitizer_cov_trace_div4",
        "__sanitizer_cov_trace_div8",
        "__sanitizer_cov_trace_gep",
        "__sanitizer_weak_hook_memcmp",
        "__sanitizer_weak_hook_strncmp",
        "__sanitizer_weak_hook_strcmp",
        "__sanitizer_weak_hook_strncasecmp",
        "__sanitizer_weak_hook_strcasecmp",
        "__sanitizer_weak_hook_strstr",
        "__sanitizer_weak_hook_strcasestr",
        "__sanitizer_weak_hook_memmem",
    ];
    let mut file = File::open(elf_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let elf = ElfFile::parse(&*buffer)?;
    let mut symbol_addresses = vec![0; targets.len()];
    for sym in elf.symbols() {
        if let Ok(name) = sym.name() {
            if let Some(pos) = targets.iter().position(|&t| t == name) {
                symbol_addresses[pos] = sym.address();
            }
        }
    }
    let mut out = format!("{}", symbol_addresses.len());
    for (idx, addr) in symbol_addresses.iter().enumerate() {
        out = format!("{}\n{}, {:x}", out, idx, addr);
    }
    Ok(out)
}
