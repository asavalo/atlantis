import unittest
import psutil
import random
import os

from libmsa import set_cpu_affinity

class TestSetCpuAffinity(unittest.TestCase):
    def test_set_cpu_affinity(self):
        self.num_tests = 10

        available_cpus = list(range(psutil.cpu_count()))
        print(f'Number of available cpus: {len(available_cpus)}')
        print(f'Cpu: {available_cpus}')

        for _ in range(self.num_tests):
            if len(available_cpus) < 2:
                self.skipTest("Not enough CPUs available to test CPU affinity.")
            
            target_cpus = [random.randint(0, len(available_cpus)  - 1)]
            set_cpu_affinity(target_cpus)
            
            process = psutil.Process(os.getpid())
            self.assertEqual(process.cpu_affinity(), target_cpus, "CPU affinity for process not set correctly.")

            for thread in process.threads():
                thread_process = psutil.Process(thread.id)
                self.assertEqual(thread_process.cpu_affinity(), target_cpus, f"CPU affinity for thread {thread.id} not set correctly.")
        

if __name__ == '__main__':
    unittest.main()