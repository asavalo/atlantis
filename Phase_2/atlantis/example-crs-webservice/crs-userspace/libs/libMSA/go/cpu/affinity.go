package cpu

import (
	"fmt"
	"os"
	"golang.org/x/sys/unix"
)

// setCPUAffinity sets the CPU affinity for the current process
func SetCPUAffinity(cpus []int) error {
	// Get the current process ID
	pid := os.Getpid()

	// Create a CPU mask
	var mask unix.CPUSet
	for _, cpu := range cpus {
		mask.Set(cpu)
	}

	// Set CPU affinity for the process
	if err := unix.SchedSetaffinity(pid, &mask); err != nil {
		return fmt.Errorf("failed to set CPU affinity for process %d: %v", pid, err)
	}

	return nil
}