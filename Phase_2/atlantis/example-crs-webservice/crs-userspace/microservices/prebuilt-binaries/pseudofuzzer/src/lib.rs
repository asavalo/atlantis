use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use clap::Parser;

/// A simple frontend that allows you to run the target application's
/// `LLVMFuzzerTestOneInput()` with input data from a file.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// File containing the input data to pass to
    /// `LLVMFuzzerTestOneInput()`
    input: PathBuf,
}

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize);
}

fn run_llvm_fuzzer_test_one_input(input: &[u8]) {
    // SAFETY: The program under test might crash depending on what
    // specific input we give it, but there's nothing we can do about
    // that, and it's kind of the goal anyway
    unsafe {
        LLVMFuzzerTestOneInput(input.as_ptr(), input.len());
    }
}

fn parse_args(argc: i32, argv: *const *const u8) -> Vec<OsString> {
    // SAFETY: This function should be safe as long as argc and argv
    // conform to their usual structures.
    let argc = argc.max(0) as usize;
    let mut args = Vec::with_capacity(argc);
    for i in 0..argc {
        let ptr = unsafe { *argv.add(i) };
        let mut length = 0;
        while unsafe { *ptr.add(length) } != 0 {
            length += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, length) };
        let os_string = OsStr::from_bytes(slice).to_owned();
        args.push(os_string);
    }
    args
}

#[no_mangle]
pub extern "C" fn libfuzzer_main(argc: i32, argv: *const *const u8) -> i32 {
    let cli = Cli::parse_from(parse_args(argc, argv));

    let input_data = std::fs::read(&cli.input)
        .unwrap_or_else(|e| panic!("failed to read input file \"{}\": {e}", cli.input.display()));

    run_llvm_fuzzer_test_one_input(&input_data);

    println!("Execution finished");

    0
}
