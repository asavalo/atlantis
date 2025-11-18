use gimli::{Dwarf, RunTimeEndian};
use object::{Endianness, File as ELFFile, Object, ObjectSection};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    borrow, fs,
    path::{self, PathBuf},
};

use crate::common::Error;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SrcLocation {
    pub src_path: String,
    pub line: u64,
    pub column: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SymCCMap {
    pub inner: HashMap<u64, SrcLocation>,
}

/// Represents a DWARF variable
#[derive(Debug, Clone, Serialize)]
pub struct DwarfVariable {
    /// Name of the variable
    pub name: String,
    /// Type of the variable (if available)
    pub var_type: Option<String>,
    /// Source file path
    pub file_path: Option<String>,
    /// Line number
    pub line: Option<u64>,
    /// Column number
    pub column: Option<u64>,
}

/// Represents a DWARF line entry
#[derive(Debug, Clone, Serialize)]
pub struct DwarfLineInfo {
    /// Source file path
    pub file_path: String,
    /// Directory path
    pub directory: Option<String>,
    /// Line number
    pub line: u64,
    /// Column number
    pub column: Option<u64>,
    /// Address in the executable
    pub address: u64,
}

mod hashing {
    /// FNV-1a 64-bit hash
    pub fn hash_bytes(data: &[u8]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for &b in data {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Boost-style hash_combine
    pub fn hash_combine(a: u64, b: u64) -> u64 {
        a ^ (b
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(a << 6)
            .wrapping_add(a >> 2))
    }

    /// Sequentially combines dir, src, line, and col into a portable pc_id
    pub fn compute_pc_id(dir: &str, src: &str, line: u64, col: u64) -> u64 {
        let h_dir = hash_bytes(dir.as_bytes());
        let h_src = hash_bytes(src.as_bytes());
        let h_line = hash_bytes(&line.to_le_bytes());
        let h_col = hash_bytes(&col.to_le_bytes());

        let mut pc_id = h_dir;
        pc_id = hash_combine(pc_id, h_src);
        pc_id = hash_combine(pc_id, h_line);
        pc_id = hash_combine(pc_id, h_col);

        pc_id = (pc_id & 0xFFFF_FFFF) | (1u64 << 63);
        pc_id
    }
}

/// Entrypoint
pub fn parse_symcc_map(elf_path: &PathBuf) -> Result<SymCCMap, Error> {
    let data = fs::read(elf_path)?;
    let object = ELFFile::parse(&*data)?;
    let endian = match object.endianness() {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
    };
    extract_map(&object, endian)
}

fn extract_map(object: &object::File, endian: gimli::RunTimeEndian) -> Result<SymCCMap, Error> {
    // Load a section and return as `Cow<[u8]>`.
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, Error> {
        Ok(match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => borrow::Cow::Borrowed(&[]),
        })
    };

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section = |section| gimli::EndianSlice::new(borrow::Cow::as_ref(section), endian);

    // Load all of the sections.
    let dwarf_sections = Dwarf::load(&load_section)?;

    // Create `EndianSlice`s for all of the sections.
    let dwarf = dwarf_sections.borrow(borrow_section);

    // Iterate over the compilation units.
    let mut ret = SymCCMap::default();
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;

        // Get the line program for the compilation unit.
        if let Some(program) = unit.line_program.clone() {
            let comp_dir = if let Some(ref dir) = unit.comp_dir {
                path::PathBuf::from(dir.to_string_lossy().into_owned())
            } else {
                path::PathBuf::new()
            };

            // Iterate over the line program rows.
            let mut rows = program.rows();
            while let Some((header, row)) = rows.next_row()? {
                if row.end_sequence() {
                    // End of sequence indicates a possible gap in addresses.
                    continue;
                } else {
                    // Determine the path. Real applications should cache this for performance.
                    if let Some(file) = row.file(header) {
                        // The directory index 0 is defined to correspond to the compilation unit directory.
                        let directory = if file.directory_index() != 0 {
                            if let Some(dir) = file.directory(header) {
                                dwarf.attr_string(&unit, dir)?.to_string()?
                            } else {
                                return Err(Error::invalid_data(format!(
                                    "Invalid directory index {}",
                                    file.directory_index()
                                )));
                            }
                        } else {
                            comp_dir.to_str().unwrap()
                        };
                        let file = dwarf.attr_string(&unit, file.path_name())?.to_string()?;
                        // Determine line/column. DWARF line/column is never 0, so we use that
                        // but other applications may want to display this differently.
                        let line = match row.line() {
                            Some(line) => line.get(),
                            None => 0,
                        };
                        let column = match row.column() {
                            gimli::ColumnType::LeftEdge => 0,
                            gimli::ColumnType::Column(column) => column.get(),
                        };
                        let pcid = hashing::compute_pc_id(directory, file, line, column);
                        let mut src_path = PathBuf::from(directory);
                        src_path.push(file);
                        ret.inner.insert(
                            pcid,
                            SrcLocation {
                                src_path: src_path.to_str().unwrap().to_string(),
                                line,
                                column,
                            },
                        );
                    }
                }
            }
        }
    }
    Ok(ret)
}
