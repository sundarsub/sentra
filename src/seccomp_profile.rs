//! Seccomp profile parsing and application for openclaw_launcher
//!
//! This module reads seccomp profiles from policy.yaml and applies them
//! using libseccomp. Profiles support inheritance via the `extends` field.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Action to take for a syscall
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SeccompAction {
    Allow,
    Deny,
    Log,
    Trap,
}

impl Default for SeccompAction {
    fn default() -> Self {
        SeccompAction::Allow
    }
}

/// Conditional rule for syscall filtering (e.g., clone with CLONE_THREAD check)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalRule {
    /// Argument index (0-5)
    pub arg: u32,
    /// Bitmask for comparison
    pub mask: u64,
    /// Value to compare against (after masking)
    pub value: u64,
    /// Action to take when condition matches
    pub action: SeccompAction,
}

/// Network policy for the profile (enforced externally via iptables/nftables)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NetworkPolicy {
    /// Allow localhost/loopback connections
    #[serde(default)]
    pub allow_loopback: bool,
    /// Allowed outbound destinations (e.g., "*.whatsapp.net:443")
    #[serde(default)]
    pub allow_outbound: Vec<String>,
}

/// A seccomp profile that can be applied to a process
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeccompProfile {
    /// Default action for syscalls not explicitly listed
    #[serde(default)]
    pub default: SeccompAction,

    /// Parent profile to inherit from
    #[serde(default)]
    pub extends: Option<String>,

    /// Syscalls to explicitly allow
    #[serde(default)]
    pub allow: Vec<String>,

    /// Syscalls to deny
    #[serde(default)]
    pub deny: Vec<String>,

    /// Dangerous syscalls to deny (separate list for clarity)
    #[serde(default)]
    pub deny_dangerous: Vec<String>,

    /// Conditional rules for specific syscalls
    #[serde(default)]
    pub conditional: HashMap<String, Vec<ConditionalRule>>,

    /// Network policy (not enforced by seccomp, but by wrapper scripts)
    #[serde(default)]
    pub network_policy: Option<NetworkPolicy>,
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self {
            default: SeccompAction::Allow,
            extends: None,
            allow: Vec::new(),
            deny: Vec::new(),
            deny_dangerous: Vec::new(),
            conditional: HashMap::new(),
            network_policy: None,
        }
    }
}

impl SeccompProfile {
    /// Resolve a profile by name, following the inheritance chain
    pub fn resolve(
        name: &str,
        profiles: &HashMap<String, SeccompProfile>,
    ) -> Result<SeccompProfile, SeccompProfileError> {
        let profile = profiles
            .get(name)
            .ok_or_else(|| SeccompProfileError::ProfileNotFound(name.to_string()))?;

        let mut resolved = profile.clone();

        // Follow extends chain (with cycle detection)
        if let Some(parent_name) = &resolved.extends {
            if parent_name == name {
                return Err(SeccompProfileError::CyclicInheritance(name.to_string()));
            }
            let parent = Self::resolve(parent_name, profiles)?;
            resolved = Self::merge(parent, resolved);
        }

        Ok(resolved)
    }

    /// Merge child profile over parent (child overrides)
    fn merge(parent: SeccompProfile, child: SeccompProfile) -> SeccompProfile {
        SeccompProfile {
            default: child.default,
            extends: None, // Already resolved
            allow: [parent.allow, child.allow].concat(),
            deny: [parent.deny, child.deny].concat(),
            deny_dangerous: [parent.deny_dangerous, child.deny_dangerous].concat(),
            conditional: {
                let mut merged = parent.conditional;
                merged.extend(child.conditional);
                merged
            },
            network_policy: child.network_policy.or(parent.network_policy),
        }
    }

    /// Get all syscalls that should be denied
    pub fn all_denied_syscalls(&self) -> Vec<&str> {
        self.deny
            .iter()
            .chain(self.deny_dangerous.iter())
            .map(|s| s.as_str())
            .collect()
    }
}

/// Launcher configuration from policy.yaml
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LauncherConfig {
    /// Default seccomp profile name
    #[serde(default)]
    pub default_profile: Option<String>,

    /// Execwall integration settings
    #[serde(default)]
    pub execwall: ExecwallConfig,

    /// OpenClaw settings
    #[serde(default)]
    pub openclaw: OpenClawConfig,
}

/// Execwall integration configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecwallConfig {
    /// Enable Execwall integration
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Mode: "repl" or "api"
    #[serde(default = "default_repl")]
    pub mode: String,

    /// Path to Execwall binary
    #[serde(default = "default_execwall_binary")]
    pub binary: String,

    /// Path to shell wrapper script
    #[serde(default = "default_shell_wrapper")]
    pub shell_wrapper: String,

    /// Path to python_runner binary
    #[serde(default = "default_python_runner")]
    pub python_runner: String,
}

impl Default for ExecwallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "repl".to_string(),
            binary: "/usr/local/bin/execwall".to_string(),
            shell_wrapper: "/usr/local/bin/execwall-shell".to_string(),
            python_runner: "/usr/lib/execwall/python_runner".to_string(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_repl() -> String {
    "repl".to_string()
}
fn default_execwall_binary() -> String {
    "/usr/local/bin/execwall".to_string()
}
fn default_shell_wrapper() -> String {
    "/usr/local/bin/execwall-shell".to_string()
}
fn default_python_runner() -> String {
    "/usr/lib/execwall/python_runner".to_string()
}

/// OpenClaw configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenClawConfig {
    /// Path to OpenClaw binary
    #[serde(default = "default_openclaw_binary")]
    pub binary: String,

    /// Gateway port
    #[serde(default = "default_gateway_port")]
    pub gateway_port: u16,
}

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            binary: "/usr/local/bin/openclaw".to_string(),
            gateway_port: 18789,
        }
    }
}

fn default_openclaw_binary() -> String {
    "/usr/local/bin/openclaw".to_string()
}
fn default_gateway_port() -> u16 {
    18789
}

/// Root structure for parsing seccomp-related sections from policy.yaml
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicySeccompConfig {
    /// Seccomp profiles
    #[serde(default)]
    pub seccomp_profiles: HashMap<String, SeccompProfile>,

    /// Launcher configuration
    #[serde(default)]
    pub launcher: LauncherConfig,
}

/// Errors that can occur when working with seccomp profiles
#[derive(Debug)]
pub enum SeccompProfileError {
    /// Profile not found in configuration
    ProfileNotFound(String),
    /// Cyclic inheritance detected
    CyclicInheritance(String),
    /// Failed to read policy file
    IoError(std::io::Error),
    /// Failed to parse YAML
    YamlError(serde_yaml::Error),
    /// Failed to apply seccomp filter
    SeccompError(String),
}

impl std::fmt::Display for SeccompProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileNotFound(name) => write!(f, "Seccomp profile not found: {}", name),
            Self::CyclicInheritance(name) => {
                write!(f, "Cyclic inheritance detected in profile: {}", name)
            }
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::YamlError(e) => write!(f, "YAML parse error: {}", e),
            Self::SeccompError(msg) => write!(f, "Seccomp error: {}", msg),
        }
    }
}

impl std::error::Error for SeccompProfileError {}

impl From<std::io::Error> for SeccompProfileError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_yaml::Error> for SeccompProfileError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::YamlError(e)
    }
}

/// Load seccomp profiles and launcher config from a policy.yaml file
pub fn load_from_policy<P: AsRef<Path>>(
    path: P,
) -> Result<PolicySeccompConfig, SeccompProfileError> {
    let content = std::fs::read_to_string(path)?;
    let config: PolicySeccompConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}

/// Apply a seccomp profile to the current process (Linux only)
#[cfg(target_os = "linux")]
pub fn apply_seccomp_profile(
    profile: &SeccompProfile,
    verbose: bool,
) -> Result<(), SeccompProfileError> {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
    use nix::libc;

    // Set NO_NEW_PRIVS (required for unprivileged seccomp)
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(SeccompProfileError::SeccompError(
                "Failed to set NO_NEW_PRIVS".to_string(),
            ));
        }
    }

    // Create filter with default action
    let default_action = match profile.default {
        SeccompAction::Allow => ScmpAction::Allow,
        SeccompAction::Deny => ScmpAction::Errno(libc::EPERM),
        SeccompAction::Log => ScmpAction::Log,
        SeccompAction::Trap => ScmpAction::Trap,
    };

    let mut filter = ScmpFilterContext::new_filter(default_action)
        .map_err(|e| SeccompProfileError::SeccompError(e.to_string()))?;

    // Apply deny rules
    for syscall_name in profile.all_denied_syscalls() {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            filter
                .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
                .map_err(|e| SeccompProfileError::SeccompError(e.to_string()))?;
            if verbose {
                println!("  → Deny: {}", syscall_name);
            }
        } else if verbose {
            println!("  → Warning: Unknown syscall: {}", syscall_name);
        }
    }

    // Apply allow rules (only meaningful if default is deny)
    if matches!(profile.default, SeccompAction::Deny) {
        for syscall_name in &profile.allow {
            if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                filter
                    .add_rule(ScmpAction::Allow, syscall)
                    .map_err(|e| SeccompProfileError::SeccompError(e.to_string()))?;
                if verbose {
                    println!("  → Allow: {}", syscall_name);
                }
            }
        }
    }

    // Apply conditional rules
    for (syscall_name, rules) in &profile.conditional {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            for rule in rules {
                let action = match rule.action {
                    SeccompAction::Allow => ScmpAction::Allow,
                    SeccompAction::Deny => ScmpAction::Errno(libc::EPERM),
                    SeccompAction::Log => ScmpAction::Log,
                    SeccompAction::Trap => ScmpAction::Trap,
                };

                filter
                    .add_rule_conditional(
                        action,
                        syscall,
                        &[ScmpArgCompare::new(
                            rule.arg,
                            ScmpCompareOp::MaskedEqual(rule.mask),
                            rule.value,
                        )],
                    )
                    .map_err(|e| SeccompProfileError::SeccompError(e.to_string()))?;

                if verbose {
                    println!(
                        "  → Conditional {}: arg{}[mask={:#x}]=={:#x} -> {:?}",
                        syscall_name, rule.arg, rule.mask, rule.value, rule.action
                    );
                }
            }
        }
    }

    // Load the filter - THIS IS IRREMOVABLE
    filter
        .load()
        .map_err(|e| SeccompProfileError::SeccompError(e.to_string()))?;

    if verbose {
        println!("  → Seccomp filter loaded (irremovable)");
    }

    Ok(())
}

/// Non-Linux stub for apply_seccomp_profile
#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_profile(
    _profile: &SeccompProfile,
    verbose: bool,
) -> Result<(), SeccompProfileError> {
    if verbose {
        println!("  → Seccomp not available on this platform (non-Linux)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_resolution_simple() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "base".to_string(),
            SeccompProfile {
                default: SeccompAction::Allow,
                deny: vec!["fork".to_string()],
                ..Default::default()
            },
        );

        let resolved = SeccompProfile::resolve("base", &profiles).unwrap();
        assert_eq!(resolved.deny, vec!["fork"]);
    }

    #[test]
    fn test_profile_inheritance() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "base".to_string(),
            SeccompProfile {
                default: SeccompAction::Allow,
                deny: vec!["fork".to_string()],
                deny_dangerous: vec!["ptrace".to_string()],
                ..Default::default()
            },
        );
        profiles.insert(
            "child".to_string(),
            SeccompProfile {
                extends: Some("base".to_string()),
                deny: vec!["vfork".to_string()],
                allow: vec!["socket".to_string()],
                ..Default::default()
            },
        );

        let resolved = SeccompProfile::resolve("child", &profiles).unwrap();

        // Should have both parent and child deny rules
        assert!(resolved.deny.contains(&"fork".to_string()));
        assert!(resolved.deny.contains(&"vfork".to_string()));
        assert!(resolved.deny_dangerous.contains(&"ptrace".to_string()));
        assert!(resolved.allow.contains(&"socket".to_string()));
    }

    #[test]
    fn test_profile_not_found() {
        let profiles = HashMap::new();
        let result = SeccompProfile::resolve("nonexistent", &profiles);
        assert!(matches!(
            result,
            Err(SeccompProfileError::ProfileNotFound(_))
        ));
    }

    #[test]
    fn test_all_denied_syscalls() {
        let profile = SeccompProfile {
            deny: vec!["fork".to_string(), "vfork".to_string()],
            deny_dangerous: vec!["ptrace".to_string(), "mount".to_string()],
            ..Default::default()
        };

        let denied = profile.all_denied_syscalls();
        assert_eq!(denied.len(), 4);
        assert!(denied.contains(&"fork"));
        assert!(denied.contains(&"ptrace"));
    }

    #[test]
    fn test_parse_yaml_config() {
        let yaml = r#"
seccomp_profiles:
  test_profile:
    default: allow
    deny:
      - fork
      - vfork
    conditional:
      clone:
        - arg: 0
          mask: 0x10000
          value: 0
          action: deny

launcher:
  default_profile: test_profile
  execwall:
    enabled: true
    mode: repl
"#;

        let config: PolicySeccompConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.seccomp_profiles.contains_key("test_profile"));
        let profile = &config.seccomp_profiles["test_profile"];
        assert_eq!(profile.deny, vec!["fork", "vfork"]);
        assert!(profile.conditional.contains_key("clone"));

        assert_eq!(
            config.launcher.default_profile,
            Some("test_profile".to_string())
        );
        assert!(config.launcher.execwall.enabled);
        assert_eq!(config.launcher.execwall.mode, "repl");
    }
}
