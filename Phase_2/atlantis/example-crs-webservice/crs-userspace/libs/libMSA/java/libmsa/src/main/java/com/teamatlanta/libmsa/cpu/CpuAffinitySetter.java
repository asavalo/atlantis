package com.teamatlanta.libmsa.cpu;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

import java.lang.management.ManagementFactory;

public class CpuAffinitySetter {

    // Interface to the C library (libc) to access native Linux calls
    interface LibC extends com.sun.jna.Library {
        LibC INSTANCE = Native.load("c", LibC.class);

        // sched_setaffinity syscall to set CPU affinity
        int sched_setaffinity(int pid, int cpusetsize, Pointer cpuset);
    }

    public static void setCpuAffinity(int[] cpus) {
        int pid = getPid(); // Get the current process ID

        if (pid < 0) {
            System.out.println("Unable to get the process ID.");
            return;
        }

        try {
            setProcessCpuAffinity(pid, cpus);
            System.out.println("CPU affinity set successfully for process: " + pid);
        } catch (Exception e) {
            System.out.println("Error setting CPU affinity: " + e.getMessage());
        }
    }

    private static int getPid() {
        String processName = ManagementFactory.getRuntimeMXBean().getName();
        return Integer.parseInt(processName.split("@")[0]);
    }

    private static void setProcessCpuAffinity(int pid, int[] cpus) {
        // Create the CPU set mask
        IntByReference cpuset = new IntByReference(0);
        for (int cpu : cpus) {
            cpuset.setValue(cpuset.getValue() | (1 << cpu));
        }

        // Set CPU affinity using sched_setaffinity syscall
        int result = LibC.INSTANCE.sched_setaffinity(pid, Integer.SIZE / 8, cpuset.getPointer());
        if (result != 0) {
            throw new RuntimeException("Failed to set CPU affinity for process: " + pid);
        }
    }
}