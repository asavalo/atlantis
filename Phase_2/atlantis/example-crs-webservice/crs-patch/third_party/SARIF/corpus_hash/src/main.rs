use libafl::inputs::{BytesInput, Input};
use std::env;
use std::fs;
use std::io;
use std::path::Path;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <file location>", args[0]);
        return Ok(());
    }
    
    let file_path = &args[1];
    
    if !Path::new(file_path).exists() {
        println!("Error: can not find  '{}'", file_path);
        return Ok(());
    }
    
    let bytes = fs::read(file_path)?;
    
    let input = BytesInput::new(bytes);
    
    let name = input.generate_name(None);
    println!("{}", name);
    
    Ok(())
}
