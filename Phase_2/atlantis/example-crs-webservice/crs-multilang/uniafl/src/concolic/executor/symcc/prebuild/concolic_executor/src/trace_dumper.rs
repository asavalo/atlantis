pub(crate) mod format {
    use libafl::observers::concolic::{SymExpr, SymExprRef};
    use std::io::Write;

    pub(crate) fn dump_trace(messages: &[(SymExprRef, SymExpr)]) -> anyhow::Result<()> {
        if let Ok(file_path) = std::env::var("SYMCC_TRACE_FILE") {
            let mut file = std::fs::File::create(file_path)?;
            let use_json = std::env::var("SYMCC_TRACE_JSON").is_ok();
            let serialized_bytes: Vec<u8> = if use_json {
                serde_json::to_vec(messages)?
            } else {
                postcard::to_stdvec(messages)?
            };
            file.write_all(&serialized_bytes)?;
        }
        Ok(())
    }
}
