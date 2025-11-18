multilang_specific_ss = ss.source_set()

multilang_specific_ss.add(files(
  'concolic-multilang.c'
))

subdir('go')
subdir('c')

specific_ss.add_all(multilang_specific_ss)
