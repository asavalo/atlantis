libfuzzer_specific_ss = ss.source_set()

libfuzzer_specific_ss.add(files(
  'libfuzzer-hooks.c',
  'libfuzzer-shm.c'
))

specific_ss.add_all(libfuzzer_specific_ss)
