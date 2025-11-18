extern int libfuzzer_main(int argc, char **argv);


int __attribute__((weak)) main(int argc, char **argv) {
    return libfuzzer_main(argc, argv);
}
