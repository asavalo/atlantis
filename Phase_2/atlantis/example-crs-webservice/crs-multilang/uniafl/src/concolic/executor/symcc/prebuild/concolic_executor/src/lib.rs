use libc::{sigaction, siginfo_t, SA_SIGINFO, SIGABRT, SIGSEGV};
use rand::Rng;
use std::mem::zeroed;
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::{fs, process::exit};
use symcc_runtime::tracing::TracingRuntimeDebug;
use trace_dumper::format::dump_trace;
// don't import SymExpr here. It will conflict with the *mut c_void type alias in symcc_runtime
// bindings
#[allow(non_snake_case)]
use symcc_runtime::{export_runtime, function_call_hook::FunctionCallHook, Runtime};

mod trace_dumper;

fn env_flag_to_bool(env_var: std::result::Result<String, std::env::VarError>) -> bool {
    match env_var {
        Ok(value) => value == "1" || value == "true" || value == "TRUE",
        Err(_) => false,
    }
}

fn get_function_call_hook() -> anyhow::Result<FunctionCallHook> {
    if let Ok(env_var) = std::env::var("SYMCC_FUNCTION_CALL_HOOK") {
        let env_var = env_var.trim();
        if env_var.is_empty() {
            return Err(anyhow::anyhow!(
                "SYMCC_FUNCTION_CALL_HOOK is empty. Please set it to a valid function call hook."
            ));
        }
        let python_code = fs::read_to_string(env_var)?;
        let function_call_hook =
            FunctionCallHook::new(&python_code).expect("Failed to create function call hook");
        return Ok(function_call_hook);
    } else {
        let function_call_hook =
            FunctionCallHook::new("").expect("Failed to create function call hook");
        return Ok(function_call_hook);
    }
}

export_runtime!(
    {
        let trace_locations = env_flag_to_bool(std::env::var("SYMCC_TRACE_LOCATIONS"));
        let function_call_hook = get_function_call_hook().expect("Failed to get function call hook");
        TracingRuntimeDebug::new(trace_locations, function_call_hook) }=> TracingRuntimeDebug
);

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize);
    fn LLVMFuzzerInitialize() -> i32;
    fn symcc_make_symbolic(data: *mut u8, size: usize);
}

fn execute_single_input(input_bytes: &[u8]) {
    unsafe {
        LLVMFuzzerInitialize();
        symcc_make_symbolic(input_bytes.as_ptr() as *mut u8, input_bytes.len());
        let data_length = _sym_build_data_length(input_bytes.len() as u64);
        if !data_length.is_null() {
            _sym_set_parameter_expression(1, data_length);
        }
        setDontSymbolize(false);
        LLVMFuzzerTestOneInput(input_bytes.as_ptr(), input_bytes.len());
        setDontSymbolize(true);
    }
}

#[no_mangle]
pub extern "C" fn sym_commit() {
    with_state(|state| {
        // TODO: do we actually need to finalize the runtime here?
        // Yes and no. For all push_path_constraints, the trace length
        // is updated, so the trace can be decoded. However,
        // any other entries after that would not be included, so yes,
        // it is necessary to finalize the runtime here.
        dump_trace(state.messages()).expect("Failed to dump constraints");
    });
}

#[no_mangle]
extern "C" fn signal_handler(sig: i32, _info: *mut siginfo_t, _ucontext: *mut c_void) {
    match sig {
        SIGABRT | SIGSEGV => {
            exit(-sig);
        }
        _ => {}
    }
}

extern "C" {
    // libc
    fn atexit(func: extern "C" fn()) -> i32;
    // these three functions are defined in the symcc runtime
    fn setDontSymbolize(flag: bool);
    fn post_exited();
    fn post_end();
}

fn register_signal_handler(sig: i32) {
    unsafe {
        let mut sa: sigaction = zeroed();
        sa.sa_sigaction = signal_handler as usize;
        sa.sa_flags = SA_SIGINFO;
        sigaction(sig, &sa, null_mut());
    }
}

#[no_mangle]
pub extern "C" fn sym_post_exit() {
    // This function writes path constraint data
    sym_commit();
    unsafe {
        // These functions, under full mode, notifies the parent process
        // that we're done stepping
        post_exited();
        post_end();
    }
}

#[no_mangle]
pub extern "C" fn symcc_main(argc: i32, argv: *const *const i8) -> i32 {
    unsafe {
        atexit(sym_post_exit);
        register_signal_handler(SIGABRT);
        register_signal_handler(SIGSEGV);
    }
    match argc {
        2 => {
            let input_file: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(*argv.offset(1)) };
            let input_file_name = input_file
                .to_str()
                .expect("Failed to convert input file to string");
            // TODO: parse the contents of the flag itself, instead of assuming it will always be "1"
            let input_bytes = match fs::read(input_file_name) {
                Ok(input) => input,
                Err(e) => {
                    panic!("Failed to read input file: {}", e);
                }
            };
            execute_single_input(&input_bytes);
        }
        1 => loop {
            let rng = rand::rng();
            let random_input_bytes: Vec<u8> = rng.random_iter().collect();
            execute_single_input(&random_input_bytes);
        },
        _ => {
            for i in 1..argc {
                let input_file: &std::ffi::CStr =
                    unsafe { std::ffi::CStr::from_ptr(*argv.offset(i as isize)) };
                let input_file_name = input_file
                    .to_str()
                    .expect("Failed to convert input file to string");
                if input_file_name.starts_with("-") {
                    // emualate libfuzzer flag parsing.
                    continue;
                }
                let input_bytes = match fs::read(input_file_name) {
                    Ok(input) => input,
                    Err(e) => {
                        panic!("Failed to read input file: {}", e);
                    }
                };
                execute_single_input(&input_bytes);
            }
        }
    }

    return 0;
}
