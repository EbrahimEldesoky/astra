use anyhow::Result;

pub struct SystemInfo {
    pub initial_nofile_soft: u64,
    pub current_nofile_soft: u64,
    pub nofile_hard: u64,
    pub cpu_cores: usize,
}

/// Automatically raises RLIMIT_NOFILE to the maximum allowed by the system.
///
/// The soft limit is lifted all the way to the hard limit (capped only by the
/// kernel's `fs.nr_open` value), which prevents `EMFILE` / "Too many open
/// files" failures when thousands of sockets are in flight simultaneously.
pub fn tune_system_limits(desired_in_flight: usize) -> Result<SystemInfo> {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let (initial_soft, hard) = rlimit::Resource::NOFILE.get()?;

    // `increase_nofile_limit(u64::MAX)` raises the soft limit to the hard
    // limit without ever attempting to exceed it (unprivileged processes
    // cannot raise the hard limit). It is also a no-op when the soft limit
    // is already at the maximum.
    let mut current_soft = initial_soft;
    match rlimit::increase_nofile_limit(u64::MAX) {
        Ok(new_soft) => current_soft = new_soft,
        Err(_) => {
            // Fallback for platforms where the helper is unavailable: set
            // soft == hard directly and re-read the effective value.
            if hard > initial_soft && rlimit::Resource::NOFILE.set(hard, hard).is_ok() {
                if let Ok((effective_soft, _)) = rlimit::Resource::NOFILE.get() {
                    current_soft = effective_soft;
                }
            }
        }
    }

    // Every in-flight request may own a TCP socket. Add headroom for the
    // reactor, stdio and any auxiliary descriptors opened by the runtime.
    let required = (desired_in_flight as u64).saturating_add(1024);
    if current_soft < required {
        eprintln!(
            "⚠️  File descriptor limit is {} but this run may need up to {}.\n\
             The hard limit is {}; raise it with 'ulimit -n {}' or run with CAP_SYS_RESOURCE.",
            current_soft, required, hard, required
        );
    }

    Ok(SystemInfo {
        initial_nofile_soft: initial_soft,
        current_nofile_soft: current_soft,
        nofile_hard: hard,
        cpu_cores,
    })
}
