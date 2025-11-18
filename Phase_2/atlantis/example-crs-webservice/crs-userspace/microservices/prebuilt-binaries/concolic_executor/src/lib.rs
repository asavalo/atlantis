use std::{fs, process};

use mimalloc::MiMalloc;

use symcc_runtime::tracing::{StdShMemMessageFileWriter, TracingRuntime};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[allow(non_snake_case)]
use symcc_runtime::{
    export_runtime,
    filter::{CallStackCoverage, NoFloat},
    Runtime,
};

export_runtime!(
    NoFloat => NoFloat;
    CallStackCoverage::default() => CallStackCoverage; // QSym-style expression pruning
    TracingRuntime::new(
        StdShMemMessageFileWriter::from_stdshmem_default_env_always_succeed(), 
        false
    ) => TracingRuntime
);

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize);
    fn symcc_make_symbolic(data: *mut u8, size: usize);
}

fn execute_single_input(input_file_name: &str) {
    let input = match fs::read(input_file_name) {
        Ok(input) => input,
        Err(e) => {
            panic!("Failed to read input file: {}", e);
        }
    };
    unsafe {
        symcc_make_symbolic(input.as_ptr() as *mut u8, input.len());
        LLVMFuzzerTestOneInput(input.as_ptr(), input.len());
    }
}

#[no_mangle]
pub extern "C" fn symcc_main(argc: i32, argv: *const *const i8) -> i32 {
    match argc {
        2 => {
            let input_file: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(*argv.offset(1)) };
            let input_file_name = input_file
                .to_str()
                .expect("Failed to convert input file to string");
            execute_single_input(input_file_name);
        }
        _ => {
            let arg0 = unsafe { std::ffi::CStr::from_ptr(*argv.offset(0)) }
                .to_str()
                .unwrap();
            panic!("Usage: {} <input_file>", arg0);
        }
    }

    return 0;
}
