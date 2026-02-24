//! Linux namespace isolation for sandbox environments
//!
//! Provides mount, PID, and network namespace isolation.
//! Only functional on Linux; provides stubs on other platforms.

#[cfg(target_os = "linux")]
use std::path::Path;

/// Configuration for namespace isolation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// Create new mount namespace
    pub new_mount_ns: bool,
    /// Create new PID namespace
    pub new_pid_ns: bool,
    /// Create new network namespace (blocks all network)
    pub new_net_ns: bool,
    /// Create new user namespace (allows unprivileged operation)
    pub new_user_ns: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            new_mount_ns: true,
            new_pid_ns: true,
            new_net_ns: true,   // No network by default
            new_user_ns: false, // Requires additional UID mapping setup
        }
    }
}

/// Configuration for a bind mount
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Source path on host
    pub source: String,
    /// Target path in sandbox
    pub target: String,
    /// Mount as read-only
    pub readonly: bool,
}

impl MountConfig {
    pub fn new(source: &str, target: &str, readonly: bool) -> Self {
        Self {
            source: source.to_string(),
            target: target.to_string(),
            readonly,
        }
    }
}

/// Builder for setting up namespace filesystem
#[derive(Debug, Clone)]
pub struct NamespaceBuilder {
    mounts: Vec<MountConfig>,
    work_dir: String,
}

impl NamespaceBuilder {
    pub fn new(work_dir: &str) -> Self {
        Self {
            mounts: Vec::new(),
            work_dir: work_dir.to_string(),
        }
    }

    /// Add a bind mount
    pub fn bind_mount(&mut self, source: &str, target: &str, readonly: bool) -> &mut Self {
        self.mounts.push(MountConfig::new(source, target, readonly));
        self
    }

    /// Setup minimal filesystem for Python execution
    pub fn setup_python_sandbox(&mut self) -> &mut Self {
        // Python interpreter and libraries (read-only)
        self.bind_mount("/usr/bin/python3", "/usr/bin/python3", true);
        self.bind_mount("/usr/lib/python3", "/usr/lib/python3", true);
        self.bind_mount("/usr/lib64", "/usr/lib64", true);
        self.bind_mount("/lib", "/lib", true);
        self.bind_mount("/lib64", "/lib64", true);

        // Work directory
        self.bind_mount(&self.work_dir.clone(), "/work", false);

        self
    }

    /// Get configured mounts
    pub fn get_mounts(&self) -> &[MountConfig] {
        &self.mounts
    }
}

// Linux-specific implementation
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use std::fs;

    impl NamespaceConfig {
        /// Enter new namespaces. Call this in child process after fork.
        ///
        /// IMPORTANT: After creating a new mount namespace, we make all mounts
        /// "private" to prevent mount events from propagating back to the parent
        /// namespace. Without this, bind mounts created in the sandbox would leak
        /// into the parent namespace and accumulate over time.
        pub fn unshare(&self) -> Result<(), Box<dyn std::error::Error>> {
            let mut flags = CloneFlags::empty();

            if self.new_mount_ns {
                flags |= CloneFlags::CLONE_NEWNS;
            }
            if self.new_pid_ns {
                flags |= CloneFlags::CLONE_NEWPID;
            }
            if self.new_net_ns {
                flags |= CloneFlags::CLONE_NEWNET;
            }
            if self.new_user_ns {
                flags |= CloneFlags::CLONE_NEWUSER;
            }

            unshare(flags)?;

            // CRITICAL: Make all mounts private to prevent mount propagation
            // back to the parent namespace. Without this, bind mounts leak!
            //
            // By default, mounts are "shared" which means mount/unmount events
            // propagate between namespaces. We need to make them "private" so
            // that mounts in this namespace don't affect the parent.
            if self.new_mount_ns {
                mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                    None::<&str>,
                )?;
            }

            Ok(())
        }
    }

    impl NamespaceBuilder {
        /// Apply all configured mounts
        ///
        /// Mount ordering is critical for correctness:
        /// 1. First, apply all read-only mounts
        /// 2. Then, apply all writable mounts
        ///
        /// This ensures that writable paths (like /tmp) remain writable
        /// even if their parent (like /) was mounted read-only.
        pub fn apply_mounts(&self) -> Result<(), Box<dyn std::error::Error>> {
            // Separate mounts into read-only and writable
            let readonly_mounts: Vec<_> = self.mounts.iter().filter(|m| m.readonly).collect();
            let writable_mounts: Vec<_> = self.mounts.iter().filter(|m| !m.readonly).collect();

            // Apply read-only mounts first
            for m in &readonly_mounts {
                self.apply_single_mount(m)?;
            }

            // Apply writable mounts last (so they override any parent read-only mounts)
            for m in &writable_mounts {
                self.apply_single_mount(m)?;
            }

            Ok(())
        }

        /// Apply a single mount
        fn apply_single_mount(&self, m: &MountConfig) -> Result<(), Box<dyn std::error::Error>> {
            let source_path = Path::new(&m.source);
            let target_path = Path::new(&m.target);

            // Ensure target directory/file exists
            if source_path.is_dir() {
                fs::create_dir_all(target_path)?;
            } else {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                if !target_path.exists() {
                    fs::File::create(target_path)?;
                }
            }

            // Bind mount
            mount(
                Some(m.source.as_str()),
                m.target.as_str(),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )?;

            // Remount with appropriate permissions
            if m.readonly {
                // Remount as readonly
                mount(
                    None::<&str>,
                    m.target.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None::<&str>,
                )?;
            } else {
                // Explicitly remount as read-write
                // This is critical when the mount point is under a read-only parent
                mount(
                    None::<&str>,
                    m.target.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT,
                    None::<&str>,
                )?;
            }

            Ok(())
        }
    }
}

// Non-Linux stubs
#[cfg(not(target_os = "linux"))]
impl NamespaceConfig {
    pub fn unshare(&self) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("WARNING: namespace isolation not available on this platform");
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl NamespaceBuilder {
    pub fn apply_mounts(&self) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("WARNING: mount namespace not available on this platform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_defaults() {
        let config = NamespaceConfig::default();
        assert!(config.new_mount_ns);
        assert!(config.new_pid_ns);
        assert!(config.new_net_ns);
        assert!(!config.new_user_ns);
    }

    #[test]
    fn test_mount_config_new() {
        let mount = MountConfig::new("/source", "/target", true);
        assert_eq!(mount.source, "/source");
        assert_eq!(mount.target, "/target");
        assert!(mount.readonly);
    }

    #[test]
    fn test_namespace_builder() {
        let mut builder = NamespaceBuilder::new("/work");
        builder.bind_mount("/src", "/dst", false);

        let mounts = builder.get_mounts();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].source, "/src");
    }

    #[test]
    fn test_python_sandbox_setup() {
        let mut builder = NamespaceBuilder::new("/mywork");
        builder.setup_python_sandbox();

        let mounts = builder.get_mounts();
        assert!(mounts.len() >= 5); // At least python, libs, work dir

        // Verify work dir is included
        assert!(mounts.iter().any(|m| m.target == "/work"));
    }
}
