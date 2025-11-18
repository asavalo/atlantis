use crate::constraint_solver::solve_constraints;
use std::{fs, ptr::addr_of};
use symcc_runtime::tracing::{MemoryMessageFileWriter, TracingRuntimeDebug};

#[allow(non_snake_case)]
use symcc_runtime::{export_runtime, filter::NoFloat, Runtime};

mod constraint_dumper;
mod constraint_solver;

export_runtime!(
    NoFloat => NoFloat;
    TracingRuntimeDebug::new(MemoryMessageFileWriter::new())=> TracingRuntimeDebug
);

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize);
    fn symcc_make_symbolic(data: *mut u8, size: usize);
}

static mut INPUT_BYTES: Vec<u8> = Vec::new();

fn execute_single_input(input_file_name: &str) {
    let input = match fs::read(input_file_name) {
        Ok(input) => input,
        Err(e) => {
            panic!("Failed to read input file: {}", e);
        }
    };
    unsafe {
        INPUT_BYTES = input.clone();
        symcc_make_symbolic(input.as_ptr() as *mut u8, input.len());
        LLVMFuzzerTestOneInput(input.as_ptr(), input.len());
    }
}

pub extern "C" fn post_exit() {
    with_state(|state| {
        state
            .runtime_mut()
            .finalize()
            .expect("Failed to finalize runtime");
        solve_constraints(
            &mut state
                .runtime()
                .writer()
                .get_writer()
                .to_reader()
                .expect("Failed to get reader"),
            unsafe { &*addr_of!(INPUT_BYTES) },
        )
        .expect("Failed to solve constraints");
    });
}

extern "C" {
    fn atexit(func: extern "C" fn()) -> i32;
}

#[no_mangle]
pub extern "C" fn symcc_main(argc: i32, argv: *const *const i8) -> i32 {
    unsafe {
        atexit(post_exit);
    }
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
