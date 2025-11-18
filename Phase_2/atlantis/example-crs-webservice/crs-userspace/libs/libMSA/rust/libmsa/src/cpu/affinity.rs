use std::io;
use std::mem;

use libc::{cpu_set_t, pid_t};

pub fn set_cpu_affinity(cpus: &[usize]) -> io::Result<()> {
    let pid = unsafe { libc::getpid() };

    let mut cpuset = unsafe { mem::zeroed::<cpu_set_t>() };
    unsafe { libc::CPU_ZERO(&mut cpuset) };
    for &cpu in cpus {
        unsafe { libc::CPU_SET(cpu, &mut cpuset) };
    }

    let size = mem::size_of::<cpu_set_t>();
    let res = unsafe { libc::sched_setaffinity(pid, size, &cpuset as *const _) };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn get_cpu_affinity(pid: pid_t) -> io::Result<Vec<usize>> {
    let mut cpuset = unsafe { mem::zeroed::<cpu_set_t>() };
    let size = mem::size_of::<cpu_set_t>();
    let res = unsafe { libc::sched_getaffinity(pid, size, &mut cpuset) };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut cpus = Vec::new();
    let max_cpus = 8 * size;
    for cpu in 0..max_cpus {
        if unsafe { libc::CPU_ISSET(cpu, &cpuset) } {
            cpus.push(cpu);
        }
    }

    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_set_cpu_affinity() {
        let num_tests = 10;
        let num_cpus = num_cpus::get();
        println!("Number of available CPUs: {}", num_cpus);

        let available_cpus: Vec<usize> = (0..num_cpus).collect();
        println!("CPUs: {:?}", available_cpus);

        for _ in 0..num_tests {
            if available_cpus.len() < 2 {
                println!("Not enough CPUs available to test CPU affinity.");
                return;
            }

            let target_cpu = rand::thread_rng().gen_range(0..available_cpus.len());
            let target_cpus = vec![target_cpu];

            set_cpu_affinity(&target_cpus).expect("Failed to set CPU affinity");

            let pid = unsafe { libc::getpid() };

            let process_cpus = get_cpu_affinity(pid).expect("Failed to get CPU affinity");
            assert_eq!(
                process_cpus, target_cpus,
                "CPU affinity for process not set correctly"
            );
        }
    }
}
