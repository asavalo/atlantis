import gdb

for bp in gdb.breakpoints():
    bp.delete()
