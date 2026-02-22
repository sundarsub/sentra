//! seccomp-bpf filter builder for syscall enforcement
//!
//! This module provides seccomp-bpf filtering to block dangerous syscalls
//! in the Python sandbox. Only available on Linux.

use std::collections::HashSet;

/// Seccomp filter action
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeccompAction {
    Allow,
    Deny,
    Kill,
}

/// Seccomp profile defining syscall rules
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub default_action: SeccompAction,
    pub deny_syscalls: HashSet<String>,
    pub allow_syscalls: HashSet<String>,
}

impl SeccompProfile {
    /// Create a new profile with default allow and specified denies
    pub fn new_deny_list(deny: Vec<&str>) -> Self {
        Self {
            default_action: SeccompAction::Allow,
            deny_syscalls: deny.iter().map(|s| s.to_string()).collect(),
            allow_syscalls: HashSet::new(),
        }
    }

    /// Create profile from policy SyscallProfile definition
    pub fn from_policy_profile(profile: &crate::policy::SyscallProfile) -> Self {
        let default_action = match profile.default.as_str() {
            "allow" => SeccompAction::Allow,
            "deny" => SeccompAction::Deny,
            "kill" => SeccompAction::Kill,
            _ => SeccompAction::Allow,
        };

        Self {
            default_action,
            deny_syscalls: profile.deny.iter().cloned().collect(),
            allow_syscalls: profile.allow.iter().cloned().collect(),
        }
    }
}

/// The restricted profile for Python sandboxing
/// Blocks: process spawning, network, destructive fs ops, privilege escalation
pub fn python_restricted_profile() -> SeccompProfile {
    SeccompProfile::new_deny_list(vec![
        // Process spawning - blocks subprocess.run(), os.system()
        "execve",
        "execveat",
        // Network - blocks socket(), connect(), data exfiltration
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        // Destructive filesystem
        "unlink",
        "unlinkat",
        "rmdir",
        "rename",
        "renameat",
        "renameat2",
        // Permission changes
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "fchownat",
        // Kernel attack surface
        "ptrace",
        "mount",
        "umount2",
        "pivot_root",
        "bpf",
        "perf_event_open",
        "init_module",
        "delete_module",
        "keyctl",
        "unshare",
        "setns",
        // Privilege escalation
        "setuid",
        "setgid",
        "setresuid",
        "setresgid",
        "setgroups",
        "capset",
        // System control
        "reboot",
        "kexec_load",
        "swapon",
        "swapoff",
        "sethostname",
    ])
}

// Linux-specific implementation
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    /// Apply the seccomp filter to the current process.
    /// WARNING: This is IRREMOVABLE once applied.
    pub fn apply_filter(profile: &SeccompProfile) -> Result<(), Box<dyn std::error::Error>> {
        use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

        // Required: set NO_NEW_PRIVS before applying seccomp
        // This prevents privilege escalation and is required for unprivileged seccomp
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err("Failed to set NO_NEW_PRIVS".into());
            }
        }

        let default_scmp_action = match profile.default_action {
            SeccompAction::Allow => ScmpAction::Allow,
            SeccompAction::Deny => ScmpAction::Errno(libc::EPERM),
            SeccompAction::Kill => ScmpAction::KillProcess,
        };

        let mut filter = ScmpFilterContext::new_filter(default_scmp_action)?;

        // Add deny rules
        for syscall_name in &profile.deny_syscalls {
            if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
            }
        }

        // Add explicit allow rules (if default is deny)
        for syscall_name in &profile.allow_syscalls {
            if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                filter.add_rule(ScmpAction::Allow, syscall)?;
            }
        }

        // Load and apply the filter - THIS IS IRREMOVABLE
        filter.load()?;

        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::apply_filter;

// Non-Linux stub
#[cfg(not(target_os = "linux"))]
pub fn apply_filter(_profile: &SeccompProfile) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: seccomp not available on this platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_restricted_profile_blocks_execve() {
        let profile = python_restricted_profile();
        assert!(profile.deny_syscalls.contains("execve"));
        assert!(profile.deny_syscalls.contains("socket"));
        assert!(profile.deny_syscalls.contains("connect"));
        assert!(profile.deny_syscalls.contains("unlink"));
    }

    #[test]
    fn test_seccomp_action_equality() {
        assert_eq!(SeccompAction::Allow, SeccompAction::Allow);
        assert_ne!(SeccompAction::Allow, SeccompAction::Deny);
    }

    #[test]
    fn test_new_deny_list() {
        let profile = SeccompProfile::new_deny_list(vec!["read", "write"]);
        assert_eq!(profile.default_action, SeccompAction::Allow);
        assert!(profile.deny_syscalls.contains("read"));
        assert!(profile.deny_syscalls.contains("write"));
        assert!(profile.allow_syscalls.is_empty());
    }
}
