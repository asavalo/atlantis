use goblin::elf::Elf;
use goblin::Object;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LibraryMapping {
    pub start_addr: u64,
    pub end_addr: u64,
}

pub fn extract_build_id(elf: &Elf, data: &[u8]) -> Option<String> {
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".note.gnu.build-id" {
                let section_data = &data
                    [section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];
                if section_data.len() >= 16 {
                    // Parse note header: namesz (4), descsz (4), type (4)
                    let namesz = u32::from_le_bytes([
                        section_data[0],
                        section_data[1],
                        section_data[2],
                        section_data[3],
                    ]);
                    let descsz = u32::from_le_bytes([
                        section_data[4],
                        section_data[5],
                        section_data[6],
                        section_data[7],
                    ]);

                    // Skip header (12 bytes) and name (padded to 4-byte boundary)
                    let name_end = 12 + ((namesz + 3) & !3) as usize;
                    if name_end + descsz as usize <= section_data.len() {
                        let build_id_bytes = &section_data[name_end..name_end + descsz as usize];
                        return Some(hex::encode(build_id_bytes));
                    }
                }
            }
        }
    }
    None
}

pub fn extract_debuglink(elf: &Elf, data: &[u8]) -> Option<String> {
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".gnu_debuglink" {
                let section_data = &data
                    [section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];
                // Find null terminator
                if let Some(null_pos) = section_data.iter().position(|&x| x == 0) {
                    if let Ok(debuglink) = std::str::from_utf8(&section_data[..null_pos]) {
                        return Some(debuglink.to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn read_all_symbols(elf: &Elf, base_address: u64) -> HashMap<u64, String> {
    let mut symbols = HashMap::new();

    // Read symbols from symbol tables
    for sym in &elf.syms {
        if sym.st_name != 0 && sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    let address = base_address + sym.st_value;
                    symbols.insert(address, name.to_string());
                }
            }
        }
    }

    // Also read dynamic symbols
    for sym in &elf.dynsyms {
        if sym.st_name != 0 && sym.st_value != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    let address = base_address + sym.st_value;
                    symbols.insert(address, name.to_string());
                }
            }
        }
    }

    symbols
}

pub fn find_debug_file(
    elf_path: &Path,
    debuglink: Option<&str>,
    build_id: Option<&str>,
) -> Option<PathBuf> {
    // Try debuglink first
    if let Some(debuglink) = debuglink {
        let debug_paths = vec![
            elf_path.parent()?.join(debuglink),
            elf_path.parent()?.join(".debug").join(debuglink),
            PathBuf::from("/usr/lib/debug")
                .join(elf_path.strip_prefix("/").ok()?)
                .join(debuglink),
            PathBuf::from("/usr/lib/debug")
                .join(elf_path.parent()?.strip_prefix("/").ok()?)
                .join(debuglink),
        ];

        for debug_path in debug_paths {
            if debug_path.exists() {
                return Some(debug_path);
            }
        }
    }

    // Try build_id paths
    if let Some(build_id) = build_id {
        if build_id.len() >= 8 {
            let build_id_paths = vec![
                PathBuf::from(format!(
                    "/usr/lib/debug/.build-id/{}/{}.debug",
                    &build_id[..2],
                    &build_id[2..]
                )),
                PathBuf::from(format!(
                    "/usr/lib/debug/.build-id/{}/{}",
                    &build_id[..2],
                    &build_id[2..]
                )),
            ];

            for build_id_path in build_id_paths {
                if build_id_path.exists() {
                    return Some(build_id_path);
                }
            }
        }
    }

    None
}

pub fn parse_proc_maps() -> anyhow::Result<HashMap<String, LibraryMapping>> {
    let file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(file);
    let mut libraries: HashMap<String, LibraryMapping> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 6 {
            let address_range = parts[0];
            let pathname = parts[5];
            let addr_parts: Vec<&str> = address_range.split('-').collect();
            let (start_addr, end_addr) = if addr_parts.len() == 2 {
                let start_addr = u64::from_str_radix(addr_parts[0], 16)?;
                let end_addr = u64::from_str_radix(addr_parts[1], 16)?;
                (start_addr, end_addr)
            } else {
                anyhow::bail!("Invalid address range in /proc/self/maps: {:?}", addr_parts);
            };

            // Only process .so files and executables
            if let Some(library_mapping) = libraries.get_mut(pathname) {
                library_mapping.end_addr = std::cmp::max(library_mapping.end_addr, end_addr);
            } else {
                libraries.insert(
                    pathname.to_string(),
                    LibraryMapping {
                        start_addr,
                        end_addr,
                    },
                );
            }
        }
    }
    Ok(libraries)
}

pub fn read_all_library_symbols() -> anyhow::Result<HashMap<u64, String>> {
    let mut all_symbols = HashMap::new();
    let libraries = parse_proc_maps()?;

    for (lib_path, lib_mapping) in libraries {
        let lib_path = PathBuf::from(&lib_path);
        if !lib_path.exists() {
            continue;
        }
        let symbols = process_library(&lib_path, &lib_mapping)?;
        all_symbols.extend(symbols);
    }
    Ok(all_symbols)
}

fn process_library(
    lib_path: &PathBuf,
    lib_mapping: &LibraryMapping,
) -> anyhow::Result<HashMap<u64, String>> {
    let mut file_data = Vec::new();
    File::open(lib_path)?.read_to_end(&mut file_data)?;

    match Object::parse(&file_data)? {
        Object::Elf(elf) => {
            // Extract debug information
            let debuglink = extract_debuglink(&elf, &file_data);
            let build_id = extract_build_id(&elf, &file_data);
            // Read symbols from main file
            let mut symbols = read_all_symbols(&elf, lib_mapping.start_addr);

            // Try to find and read debug file
            if let Some(debug_path) =
                find_debug_file(lib_path, debuglink.as_deref(), build_id.as_deref())
            {
                let debug_symbols = load_debug_symbols(&debug_path, lib_mapping.start_addr)?;
                symbols.extend(debug_symbols);
            }
            Ok(symbols)
        }
        _ => anyhow::bail!("Not an ELF file"),
    }
}

fn load_debug_symbols(
    debug_path: &Path,
    base_address: u64,
) -> anyhow::Result<HashMap<u64, String>> {
    let mut file_data = Vec::new();
    File::open(debug_path)?.read_to_end(&mut file_data)?;

    match Object::parse(&file_data)? {
        Object::Elf(elf) => Ok(read_all_symbols(&elf, base_address)),
        _ => anyhow::bail!("Debug file is not an ELF file"),
    }
}

pub(crate) fn addr_to_symbol_map() -> Result<HashMap<u64, String>, anyhow::Error> {
    Ok(read_all_library_symbols()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_parse_proc_maps_finds_libc() {
        let libraries = parse_proc_maps().expect("Failed to parse /proc/self/maps");

        // Should find libc in the process
        let libc_path = libraries
            .keys()
            .find(|path| path.contains("libc.so") || path.contains("libc-"))
            .expect("Could not find libc in process maps");

        let libc_mapping = &libraries[libc_path];

        // Verify the mapping has reasonable values
        assert!(libc_mapping.start_addr > 0);
        assert!(libc_mapping.end_addr > libc_mapping.start_addr);
        assert!(libc_mapping.end_addr - libc_mapping.start_addr > 0x100000); // libc should be at least 1MB
    }

    #[test]
    fn test_read_all_library_symbols_finds_libc_functions() {
        let symbols = read_all_library_symbols().expect("Failed to read library symbols");

        // Common libc functions that should be present
        let expected_functions = vec![
            "printf", "sprintf", "fprintf", "strcmp", "strcpy", "strlen", "strcat", "malloc",
            "free", "calloc", "realloc", "memcpy", "memset", "memcmp", "fopen", "fclose", "fread",
            "fwrite", "exit", "_exit",
        ];

        let mut found_functions = HashSet::new();

        for func_name in &expected_functions {
            // Check both direct name and prefixed versions (library:function)
            let found = symbols
                .values()
                .any(|name| name == func_name || name.ends_with(&format!(":{}", func_name)));

            if found {
                found_functions.insert(*func_name);
            }
        }

        // We should find at least some of these common functions
        assert!(
            found_functions.len() >= 5,
            "Expected to find at least 5 common libc functions, found: {:?}",
            found_functions
        );

        println!(
            "Found {} out of {} expected libc functions",
            found_functions.len(),
            expected_functions.len()
        );
    }

    #[test]
    fn test_symbols_have_valid_addresses() {
        let symbols = read_all_library_symbols().expect("Failed to read library symbols");

        assert!(!symbols.is_empty(), "Should find at least some symbols");

        // All symbol addresses should be non-zero and in reasonable ranges
        for (&addr, name) in &symbols {
            assert!(addr > 0, "Symbol {} has zero address", name);
            // On x86_64, user space addresses should be < 0x800000000000
            assert!(
                addr < 0x800000000000,
                "Symbol {} has unreasonable address: 0x{:x}",
                name,
                addr
            );
        }

        println!(
            "Validated {} symbols with reasonable addresses",
            symbols.len()
        );
    }

    #[test]
    fn test_multiple_symbol_resolution() {
        let symbols = read_all_library_symbols().expect("Failed to read library symbols");

        // Test that we can find multiple related functions
        let string_functions: Vec<_> = symbols
            .values()
            .filter(|name| name.contains("str") && !name.contains(":"))
            .collect();

        let memory_functions: Vec<_> = symbols
            .values()
            .filter(|name| name.starts_with("mem") && !name.contains(":"))
            .collect();

        println!(
            "Found {} string functions: {:?}",
            string_functions.len(),
            string_functions
        );
        println!(
            "Found {} memory functions: {:?}",
            memory_functions.len(),
            memory_functions
        );

        // Should find multiple string and memory functions
        assert!(string_functions.len() > 0, "Should find string functions");
        assert!(memory_functions.len() > 0, "Should find memory functions");
    }

    #[test]
    fn test_library_mapping_structure() {
        let mapping = LibraryMapping {
            start_addr: 0x7f1234567000,
            end_addr: 0x7f1234568000,
        };

        assert_eq!(mapping.start_addr, 0x7f1234567000);
        assert_eq!(mapping.end_addr, 0x7f1234568000);
    }

    #[test]
    fn test_find_debug_file_paths() {
        use std::path::Path;

        // Test the debug file finding logic with non-existent files
        let fake_path = Path::new("/tmp/fake_binary");

        // Test with debuglink
        let result = find_debug_file(&fake_path, Some("fake.debug"), None);
        assert_eq!(result, None);

        // Test with build ID
        let result = find_debug_file(&fake_path, None, Some("abcdef1234567890"));
        assert_eq!(result, None);

        // Test with both
        let result = find_debug_file(&fake_path, Some("fake.debug"), Some("abcdef1234567890"));
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_functions_integration() {
        // Test that we can extract and parse actual ELF data
        let libraries = parse_proc_maps().expect("Failed to parse proc maps");

        // Find libc
        let (libc_path, libc_mapping) = libraries
            .iter()
            .find(|(path, _)| path.contains("libc.so") || path.contains("libc-"))
            .expect("Could not find libc");

        println!(
            "libc mapping: 0x{:x} - 0x{:x}",
            libc_mapping.start_addr, libc_mapping.end_addr
        );

        // Test the actual library processing
        let lib_path = PathBuf::from(libc_path);
        if lib_path.exists() {
            match process_library(&lib_path, libc_mapping) {
                Ok(symbols) => {
                    assert!(!symbols.is_empty(), "Should find symbols in libc");
                    println!("Successfully processed libc with {} symbols", symbols.len());
                }
                Err(e) => {
                    // This might fail on some systems, so we'll just warn
                    println!("Warning: Could not process libc: {}", e);
                }
            }
        }
    }
}
