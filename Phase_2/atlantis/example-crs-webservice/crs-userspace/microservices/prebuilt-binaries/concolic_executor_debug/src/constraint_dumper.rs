use libafl::observers::concolic::serialization_format::MessageFileReader;
use serde_json;
use std::io::Read;

pub fn dump_constraints<R: Read>(reader: &mut MessageFileReader<R>) -> anyhow::Result<()> {
    if let Ok(file_path) = std::env::var("SYMCC_TRACE_FILE") {
        let mut messages = vec![];
        while let Some(maybe_msg) = reader.next_message() {
            if let Ok((sym_expr_id, sym_expr)) = maybe_msg {
                messages.push((sym_expr_id.get(), sym_expr));
            } else {
                return Err(anyhow::anyhow!("Failed to read message"));
            }
        }
        let mut file = std::fs::File::create(file_path)?;
        serde_json::to_writer(&mut file, &messages)?;
    }
    Ok(())
}
