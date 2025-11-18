GDB_SCRIPT_TEMPLATE = """
set pagination off
set style enabled off
set $_exitcode = -999
set height 0
set logging file {breakpoints_out}
set logging redirect on
set logging on
handle SIGTERM nostop print pass
handle SIGPIPE nostop
define hook-stop
    if $_exitcode != -999
        quit
    end
end
{breakpoints_script}
{additional_gdb_script}
run
""".lstrip()


FILE_LINE_BREAKPOINT_SCRIPT_TEMPLATE = """
b {file}:{line}
command {index}
    {expressions}
    c
end
""".lstrip()

FUNCTION_BREAKPOINT_SCRIPT_TEMPLATE = """
b {function}
command {index}
    {expressions}
    c
end
""".lstrip()

WRAPPER_SCRIPT_TEMPLATE = """
#!/bin/sh

/work/gdb -batch-silent -ex 'source {gdb_script}' --args /out/{project_name}/{harness_name} {poc}
""".lstrip()
