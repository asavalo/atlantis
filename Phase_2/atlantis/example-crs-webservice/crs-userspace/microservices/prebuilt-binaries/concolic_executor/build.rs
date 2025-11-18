pub fn main() {
    cc::Build::new()
        .file("src/symcc_rt_main.c")
        .flag("-c")
        .compile("symcc_rt_main.c.o");
}
