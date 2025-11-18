use crate::RSymExpr;
use function_address_resolver::addr_to_symbol_map;
use libafl::observers::concolic::FailedFunctionHookReason;
use libafl::observers::concolic::FailedIntrinsicHookReason;
use pyo3::ffi::c_str;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use std::collections::HashMap;
use std::ffi::CStr;

mod function_address_resolver;

pub struct FunctionCallHook {}

const SYMCC_INTERFACES_PY: &str = concat!(
    include_str!(concat!(env!("OUT_DIR"), "/symcc_interfaces.py")),
    "\x00"
);

pub enum IntrinsicCallHookResult {
    Success {
        expr: Option<RSymExpr>,
    },
    Failure {
        intrinsic_id: u64,
        reason: FailedIntrinsicHookReason,
    },
}

pub enum FunctionCallHookResult {
    Success {
        expr: Option<RSymExpr>,
    },
    Failure {
        function_addr: u64,
        reason: FailedFunctionHookReason,
    },
}

impl FunctionCallHook {
    pub fn new(python_code: &str) -> Result<Self, anyhow::Error> {
        let addr_to_symbol_map = addr_to_symbol_map()?;
        let escaped_string = serde_json::to_string(&serde_json::to_string(&addr_to_symbol_map)?)?;
        let null_terminated_addr_to_symbol_map_code = format!(
            "import json; temp = json.loads({}); ADDR_TO_SYMBOLS = {{ int(k): v for k, v in temp.items() }};\x00",
            escaped_string
        );
        Python::with_gil(|py| -> Result<_, anyhow::Error> {
            let addr_to_symbols_module = PyModule::from_code(
                py,
                &CStr::from_bytes_with_nul(null_terminated_addr_to_symbol_map_code.as_bytes())?,
                c_str!("addr_to_symbols.py"),
                c_str!("addr_to_symbols"),
            )?;
            let symcc_interfaces = PyModule::from_code(
                py,
                &CStr::from_bytes_with_nul(SYMCC_INTERFACES_PY.as_bytes())?,
                c_str!("symcc_interfaces.py"),
                c_str!("symcc_interfaces"),
            )?;
            let null_terminated_python_code = format!("{}\x00", python_code);
            let module = PyModule::from_code(
                py,
                &CStr::from_bytes_with_nul(null_terminated_python_code.as_bytes())?,
                c_str!("emu.py"),
                c_str!("emu"),
            )?;
            let sys = PyModule::import(py, "sys")?;
            let py_modules: Bound<'_, PyDict> = sys
                .getattr(intern!(sys.py(), "modules"))?
                .downcast_into()
                .map_err(|e| anyhow::anyhow!("Failed to downcast sys.modules: {}", e))?;
            py_modules.set_item("symcc_interfaces", symcc_interfaces)?;
            py_modules.set_item("addr_to_symbols", addr_to_symbols_module)?;
            py_modules.set_item("emu", module)?;
            Ok(())
        })?;
        Ok(FunctionCallHook {})
    }

    pub fn run_intrinsic(
        &self,
        intrinsic_id: u64,
        concrete_return_value: Option<u64>,
        args: &[RSymExpr],
        concrete_args: &[Option<u64>],
    ) -> Result<(Option<RSymExpr>, Option<FailedIntrinsicHookReason>), anyhow::Error> {
        Python::with_gil(|py| -> Result<_, anyhow::Error> {
            let module = PyModule::import(py, "emu")?;
            if let Ok(handler) = module.getattr("run_intrinsic") {
                let (ret, errno, bt): (usize, usize, String) = handler
                    .call1((intrinsic_id, concrete_return_value, args, concrete_args))?
                    .extract()?;
                match errno {
                    1 => {
                        return Ok((None, Some(FailedIntrinsicHookReason::MissingFunction)));
                    }
                    2 => {
                        return Ok((None, Some(FailedIntrinsicHookReason::PythonException(bt))));
                    }
                    0 => {
                        return Ok((RSymExpr::new(ret), None));
                    }
                    _ => {
                        return Ok((
                            None,
                            Some(FailedIntrinsicHookReason::Other(format!(
                                "Unknown error code: {}",
                                errno
                            ))),
                        ));
                    }
                }
            } else {
                return Ok((
                    None,
                    Some(FailedIntrinsicHookReason::Other(
                        "Missing 'run_intrinsic'".to_string(),
                    )),
                ));
            }
        })
    }

    pub fn run_function(
        &self,
        function_addr: u64,
        concrete_return_value: Option<u64>,
        args: &[RSymExpr],
        concrete_args: &[Option<u64>],
    ) -> Result<(Option<RSymExpr>, Option<FailedFunctionHookReason>), anyhow::Error> {
        Python::with_gil(|py| -> Result<_, anyhow::Error> {
            let module = PyModule::import(py, "emu")?;
            if let Ok(handler) = module.getattr("run_function") {
                let (ret, errno, bt): (usize, usize, String) = handler
                    .call1((function_addr, concrete_return_value, args, concrete_args))?
                    .extract()?;
                match errno {
                    1 => {
                        return Ok((None, Some(FailedFunctionHookReason::MissingFunction)));
                    }
                    2 => {
                        return Ok((None, Some(FailedFunctionHookReason::PythonException(bt))));
                    }
                    0 => {
                        return Ok((RSymExpr::new(ret), None));
                    }
                    _ => {
                        return Ok((
                            None,
                            Some(FailedFunctionHookReason::Other(format!(
                                "Unknown error code: {}",
                                errno
                            ))),
                        ));
                    }
                }
            } else {
                return Ok((
                    None,
                    Some(FailedFunctionHookReason::Other(
                        "Missing 'run_function'".to_string(),
                    )),
                ));
            }
        })
    }

    pub fn hook_intrinsic_call(
        &self,
        intrinsic_id: u64,
        concrete_return_value: Option<u64>,
        args: &[RSymExpr],
        concrete_args: &[Option<u64>],
    ) -> IntrinsicCallHookResult {
        match self.run_intrinsic(intrinsic_id, concrete_return_value, args, concrete_args) {
            Ok((None, Some(reason))) => {
                eprintln!(
                    "[-] Error: None returned from intrinsic call hook for {}: {:?}",
                    intrinsic_id, reason
                );
                IntrinsicCallHookResult::Failure {
                    intrinsic_id,
                    reason,
                }
            }
            Ok((maybe_expr, None)) => IntrinsicCallHookResult::Success { expr: maybe_expr },
            Ok((a, b)) => {
                eprintln!(
                    "[-] Error: Unexpected return value from Python hook: {:?} {:?}",
                    a, b
                );
                IntrinsicCallHookResult::Failure {
                    intrinsic_id,
                    reason: FailedIntrinsicHookReason::Other(
                        "Unexpected return value from Python hook".to_string(),
                    ),
                }
            }
            Err(e) => {
                eprintln!("[-] Error running hook: {}", e);
                IntrinsicCallHookResult::Failure {
                    intrinsic_id,
                    reason: FailedIntrinsicHookReason::Other(format!("Error running hook: {}", e)),
                }
            }
        }
    }

    pub fn hook_function_call(
        &self,
        function_addr: u64,
        concrete_return_value: Option<u64>,
        args: &[RSymExpr],
        concrete_args: &[Option<u64>],
    ) -> FunctionCallHookResult {
        match self.run_function(function_addr, concrete_return_value, args, concrete_args) {
            Ok((None, Some(reason))) => FunctionCallHookResult::Failure {
                function_addr,
                reason,
            },
            Ok((maybe_expr, None)) => FunctionCallHookResult::Success { expr: maybe_expr },
            Ok((a, b)) => {
                eprintln!(
                    "[-] Error: Unexpected return value from Python hook: {:?} {:?}",
                    a, b
                );
                FunctionCallHookResult::Failure {
                    function_addr,
                    reason: FailedFunctionHookReason::Other(
                        "Unexpected return value from Python hook".to_string(),
                    ),
                }
            }
            Err(e) => {
                eprintln!("[-] Error running hook: {}", e);
                FunctionCallHookResult::Failure {
                    function_addr,
                    reason: FailedFunctionHookReason::Other(format!("Error running hook: {}", e)),
                }
            }
        }
    }
}
