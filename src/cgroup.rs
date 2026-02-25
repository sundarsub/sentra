//! Cgroup v2 resource limits for sandbox execution
//!
//! Controls memory, CPU, and process limits via Linux cgroups.
//! Only functional on Linux; provides stubs on other platforms.

use std::path::PathBuf;

/// Resource limits for sandbox execution
#[derive(Debug, Clone)]
pub struct CgroupLimits {
    /// Maximum memory in bytes
    pub memory_max_bytes: u64,
    /// CPU quota as percentage (50 = 50%)
    pub cpu_max_percent: u32,
    /// Maximum number of processes
    pub pids_max: u32,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 512 * 1024 * 1024, // 512MB
            cpu_max_percent: 50,
            pids_max: 64,
        }
    }
}

impl CgroupLimits {
    /// Create limits from policy profile
    pub fn from_policy(limits: &crate::policy::LimitsDefaults) -> Self {
        Self {
            memory_max_bytes: limits.mem_max_mb * 1024 * 1024,
            cpu_max_percent: limits.cpu_max_percent,
            pids_max: limits.pids_max,
        }
    }
}

/// Cgroup root path for execwall
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const EXECWALL_CGROUP: &str = "execwall";

/// Controller for a single cgroup execution context
#[derive(Debug)]
pub struct CgroupController {
    /// Cgroup name (e.g., "exec_abc123")
    name: String,
    /// Full path to cgroup directory
    path: PathBuf,
    /// Whether this cgroup was created by us
    created: bool,
}

impl CgroupController {
    /// Create a new cgroup for this execution
    #[cfg(target_os = "linux")]
    pub fn create(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use std::fs;

        let path = PathBuf::from(CGROUP_ROOT).join(EXECWALL_CGROUP).join(name);

        // Create the cgroup directory
        fs::create_dir_all(&path)?;

        Ok(Self {
            name: name.to_string(),
            path,
            created: true,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        eprintln!("WARNING: cgroups not available on this platform");
        Ok(Self {
            name: name.to_string(),
            path: PathBuf::from("/tmp/fake_cgroup").join(name),
            created: false,
        })
    }

    /// Set resource limits on this cgroup
    #[cfg(target_os = "linux")]
    pub fn set_limits(&self, limits: &CgroupLimits) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;

        // Memory limit: memory.max
        let mem_path = self.path.join("memory.max");
        fs::write(&mem_path, limits.memory_max_bytes.to_string())?;

        // CPU limit: cpu.max format is "$QUOTA $PERIOD"
        // For 50% CPU: "50000 100000" means 50ms out of every 100ms
        let cpu_quota = (limits.cpu_max_percent as u64) * 1000;
        let cpu_path = self.path.join("cpu.max");
        fs::write(&cpu_path, format!("{} 100000", cpu_quota))?;

        // PIDs limit: pids.max
        let pids_path = self.path.join("pids.max");
        fs::write(&pids_path, limits.pids_max.to_string())?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_limits(&self, _limits: &CgroupLimits) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Add a process to this cgroup
    #[cfg(target_os = "linux")]
    pub fn add_pid(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let procs_path = self.path.join("cgroup.procs");
        let mut file = OpenOptions::new().write(true).open(&procs_path)?;
        writeln!(file, "{}", pid)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn add_pid(&self, _pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Get current memory usage in bytes
    #[cfg(target_os = "linux")]
    pub fn get_memory_current(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(self.path.join("memory.current"))?;
        Ok(content.trim().parse()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_memory_current(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(0)
    }

    /// Get peak memory usage in bytes
    #[cfg(target_os = "linux")]
    pub fn get_memory_peak(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(self.path.join("memory.peak"))?;
        Ok(content.trim().parse()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_memory_peak(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(0)
    }

    /// Get the cgroup name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the cgroup path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for CgroupController {
    fn drop(&mut self) {
        if self.created {
            // Clean up: remove the cgroup directory
            // Note: cgroup must be empty (no processes) before removal
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_limits_default() {
        let limits = CgroupLimits::default();
        assert_eq!(limits.memory_max_bytes, 512 * 1024 * 1024);
        assert_eq!(limits.cpu_max_percent, 50);
        assert_eq!(limits.pids_max, 64);
    }

    #[test]
    #[ignore] // Requires root/cgroup access - not available in CI
    fn test_cgroup_controller_name() {
        let controller = CgroupController::create("test_exec").unwrap();
        assert_eq!(controller.name(), "test_exec");
    }

    #[test]
    fn test_cgroup_limits_memory_calculation() {
        let limits = CgroupLimits {
            memory_max_bytes: 1024 * 1024 * 1024, // 1GB
            cpu_max_percent: 100,
            pids_max: 128,
        };
        assert_eq!(limits.memory_max_bytes, 1073741824);
    }
}
