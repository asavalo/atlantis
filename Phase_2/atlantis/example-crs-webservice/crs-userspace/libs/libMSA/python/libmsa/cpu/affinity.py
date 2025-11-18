import os

import psutil


def set_cpu_affinity(cpus: list[int]) -> None:
    try:
        pid = os.getpid()
        process = psutil.Process(pid)

        process.cpu_affinity(cpus)

        for thread in process.threads():
            thread_pid = thread.id
            try:
                thread_process = psutil.Process(thread_pid)
                thread_process.cpu_affinity(cpus)
            except psutil.NoSuchProcess:
                print(f"Thread {thread_pid} no longer exists.", flush=True)
    except psutil.NoSuchProcess:
        print(f"Process does not exist or terminated.", flush=True)
