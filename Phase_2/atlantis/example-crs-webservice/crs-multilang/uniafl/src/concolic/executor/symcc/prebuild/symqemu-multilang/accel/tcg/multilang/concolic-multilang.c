#include "concolic-multilang.h"

skip_translation_t multilang_insert_hooks(CPUState *cpu, DisasContextBase *s,
                                          uint64_t pc) {
  return go_insert_hook(cpu, s, pc) || c_insert_hook(cpu, s, pc);

  // if (true /* is_go */) {
  //     return go_insert_hook(cpu, s, pc);
  // }
  // if (is_c) {
  //     return c_insert_hook(cpu, s, pc);
  // }
  // if (is_rust) {
  //     return rust_insert_hook(cpu, s, pc);
  // }
}

void multilang_module_init(char *exec_path) {

  //init_c_module(exec_path);
  //init_rust_module();
  //init_go_module(exec_path);

  return;
}

void multilang_handle_translate_loop(uint64_t pc) {

  // c_translate_loop(pc);
  // rust_translate_loop(pc);
  // go_translate_loop(pc);
}
