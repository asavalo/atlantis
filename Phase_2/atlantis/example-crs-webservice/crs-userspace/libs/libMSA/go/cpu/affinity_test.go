package cpu

import (
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSetCPUAffinity tests the setCPUAffinity function.
func TestSetCPUAffinity(t *testing.T) {
	// Number of test iterations
	numTests := 10

	// Get the available CPUs
	numCPUs := runtime.NumCPU()
	if numCPUs < 2 {
		t.Skip("Not enough CPUs available to test CPU affinity.")
	}

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < numTests; i++ {
		// Select a random CPU
		targetCPU := rand.Intn(numCPUs)
		targetCPUs := []int{targetCPU}

		// Set CPU affinity for the process
		err := SetCPUAffinity(targetCPUs)
		if err != nil {
			t.Fatalf("Failed to set CPU affinity: %v", err)
		}

		// Check CPU affinity for the current process
		pid := os.Getpid()
		var mask unix.CPUSet
		err = unix.SchedGetaffinity(pid, &mask)
		if err != nil {
			t.Fatalf("Failed to get CPU affinity for process: %v", err)
		}

		// Verify that the CPU affinity matches the target CPU
		if !mask.IsSet(targetCPU) {
			t.Errorf("CPU affinity for process not set correctly. Expected CPU %d to be set.", targetCPU)
		}
	}
}