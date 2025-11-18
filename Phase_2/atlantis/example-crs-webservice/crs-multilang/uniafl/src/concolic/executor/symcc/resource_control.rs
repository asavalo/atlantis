use crate::common::Error;
use cgroups_rs::{
    cgroup_builder::CgroupBuilder, cpu::CpuController, memory::MemController, Cgroup, CgroupPid,
    Controller,
};

#[allow(unused)]
pub fn new_cgroup(
    cgroup_name: &str,
    memory_limit: i64,
    cpu_period: u64,
    cpu_quota: i64,
) -> Result<Cgroup, Error> {
    let hier = cgroups_rs::hierarchies::auto();
    let cg: Cgroup = CgroupBuilder::new(cgroup_name)
        .memory()
        .memory_hard_limit(memory_limit)
        .memory_soft_limit(memory_limit)
        .done()
        .cpu()
        .period(cpu_period)
        .quota(cpu_quota)
        .done()
        .build(hier)?;
    let mem_controller = cg
        .controller_of::<MemController>()
        .ok_or_else(|| Error::other("Memory controller not found"))?;
    mem_controller.create();
    let cpu_contoller = cg
        .controller_of::<CpuController>()
        .ok_or_else(|| Error::other("CPU controller not found"))?;
    cpu_contoller.create();
    Ok(cg)
}

#[allow(unused)]
pub fn apply_cgroup(cgroup: &Cgroup, pid: u64) -> Result<(), Error> {
    let cgroup_pid = CgroupPid::from(pid);
    if let Some(mem_controller) = cgroup.controller_of::<MemController>() {
        mem_controller.add_task_by_tgid(&cgroup_pid)?;
    } else {
        return Err(Error::other("Memory controller not found"));
    }
    if let Some(cpu_controller) = cgroup.controller_of::<CpuController>() {
        cpu_controller.add_task_by_tgid(&cgroup_pid)?;
    } else {
        return Err(Error::other("CPU controller not found"));
    }
    Ok(())
}
