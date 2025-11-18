use constraint_dumper::dump_constraints;
use ctor::{ctor};
use symcc_runtime::tracing::{MemoryMessageFileWriter, TracingRuntimeDebug};

#[allow(non_snake_case)]
use symcc_runtime::{export_runtime, filter::NoFloat, Runtime};

mod constraint_dumper;

export_runtime!(
    NoFloat => NoFloat;
    TracingRuntimeDebug::new(MemoryMessageFileWriter::new())=> TracingRuntimeDebug
);

static mut POST_EXIT_EXECUTED: bool = false;

pub extern "C" fn post_exit() {
    if unsafe { POST_EXIT_EXECUTED } {
        return;
    }
    with_state(|state| {
        state
            .runtime_mut()
            .finalize()
            .expect("Failed to finalize runtime");
        dump_constraints(
            &mut state
                .runtime()
                .writer()
                .get_writer()
                .to_reader()
                .expect("Failed to get reader"),
        )
        .expect("Failed to solve constraints");
    });
    unsafe {
        POST_EXIT_EXECUTED = true;
    }
}

extern "C" {
    fn atexit(func: extern "C" fn()) -> i32;
}

#[ctor]
fn symcc_init() {
    unsafe {
        atexit(post_exit);
    } 
}

#[no_mangle]
extern "C" fn symcc_fini() {
    post_exit();
}

