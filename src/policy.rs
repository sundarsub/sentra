use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Policy mode - enforce blocks commands, audit only logs
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Enforce,
    Audit,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Enforce
    }
}

/// Default action when no rule matches
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    Deny,
}

impl Default for DefaultAction {
    fn default() -> Self {
        DefaultAction::Deny
    }
}

/// Effect of a rule match
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// Match criteria for a rule
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MatchCriteria {
    /// Regex pattern for executable name
    #[serde(default)]
    pub executable: Option<String>,
    /// Regex pattern for full argument string
    #[serde(default)]
    pub args_pattern: Option<String>,
    /// Identity pattern (user/service account to match)
    #[serde(default)]
    pub identity: Option<String>,
}

/// A single policy rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    /// Match criteria
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,
    /// Effect when rule matches
    pub effect: Effect,
    /// Optional reason for deny (shown to user)
    #[serde(default)]
    pub reason: Option<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Maximum commands per window (default: 60)
    #[serde(default = "default_max_commands")]
    pub max_commands: u32,
    /// Window duration in seconds (default: 60)
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

fn default_max_commands() -> u32 {
    60
}

fn default_window_seconds() -> u64 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_commands: 60,
            window_seconds: 60,
        }
    }
}

/// Complete policy file structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    /// Policy version
    #[serde(default = "default_version")]
    pub version: String,
    /// Enforcement mode
    #[serde(default)]
    pub mode: PolicyMode,
    /// Default action when no rule matches
    #[serde(default)]
    pub default: DefaultAction,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// List of rules (evaluated in order)
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: default_version(),
            mode: PolicyMode::Enforce,
            default: DefaultAction::Deny,
            rate_limit: RateLimitConfig::default(),
            rules: Vec::new(),
        }
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// Whether the command is allowed
    pub allowed: bool,
    /// The rule that matched (if any)
    pub matched_rule: Option<String>,
    /// Reason for denial (if denied)
    pub reason: Option<String>,
    /// Whether this is audit-only mode
    pub audit_mode: bool,
}

/// Parsed command for policy evaluation
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    /// The executable name (basename)
    pub executable: String,
    /// Full argument string (everything after executable)
    pub args_string: String,
    /// Original raw command
    pub raw: String,
}

impl ParsedCommand {
    /// Parse a command string into executable and arguments
    pub fn parse(command: &str) -> Self {
        let trimmed = command.trim();
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();

        let executable = parts.first()
            .map(|s| {
                // Extract basename from path
                Path::new(s).file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(s)
                    .to_string()
            })
            .unwrap_or_default();

        let args_string = if parts.len() > 1 {
            parts[1].trim().to_string()
        } else {
            String::new()
        };

        ParsedCommand {
            executable,
            args_string,
            raw: trimmed.to_string(),
        }
    }
}

/// Compiled rule with pre-compiled regex patterns
struct CompiledRule {
    id: String,
    executable_pattern: Option<Regex>,
    args_pattern: Option<Regex>,
    identity_pattern: Option<Regex>,
    effect: Effect,
    reason: Option<String>,
}

/// Policy engine that evaluates commands against rules
pub struct PolicyEngine {
    policy: Policy,
    compiled_rules: Vec<CompiledRule>,
}

impl PolicyEngine {
    /// Load and compile a policy from a YAML file
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file '{}': {}", path, e))?;

        Self::load_from_string(&content)
    }

    /// Load and compile a policy from a YAML string
    pub fn load_from_string(yaml_content: &str) -> Result<Self, String> {
        let policy: Policy = serde_yaml::from_str(yaml_content)
            .map_err(|e| format!("Failed to parse policy YAML: {}", e))?;

        Self::from_policy(policy)
    }

    /// Create engine from a Policy struct
    pub fn from_policy(policy: Policy) -> Result<Self, String> {
        let mut compiled_rules = Vec::new();

        for rule in &policy.rules {
            let executable_pattern = match &rule.match_criteria.executable {
                Some(pattern) => {
                    Some(Regex::new(pattern)
                        .map_err(|e| format!("Invalid regex in rule '{}' executable pattern: {}", rule.id, e))?)
                }
                None => None,
            };

            let args_pattern = match &rule.match_criteria.args_pattern {
                Some(pattern) => {
                    Some(Regex::new(pattern)
                        .map_err(|e| format!("Invalid regex in rule '{}' args_pattern: {}", rule.id, e))?)
                }
                None => None,
            };

            let identity_pattern = match &rule.match_criteria.identity {
                Some(pattern) => {
                    Some(Regex::new(pattern)
                        .map_err(|e| format!("Invalid regex in rule '{}' identity pattern: {}", rule.id, e))?)
                }
                None => None,
            };

            compiled_rules.push(CompiledRule {
                id: rule.id.clone(),
                executable_pattern,
                args_pattern,
                identity_pattern,
                effect: rule.effect.clone(),
                reason: rule.reason.clone(),
            });
        }

        Ok(PolicyEngine {
            policy,
            compiled_rules,
        })
    }

    /// Get the policy mode
    pub fn mode(&self) -> &PolicyMode {
        &self.policy.mode
    }

    /// Evaluate a command against the policy
    pub fn evaluate(&self, command: &str) -> EvaluationResult {
        self.evaluate_with_identity(command, None)
    }

    /// Evaluate a command against the policy with identity context
    pub fn evaluate_with_identity(&self, command: &str, identity: Option<&str>) -> EvaluationResult {
        let parsed = ParsedCommand::parse(command);

        // Check each rule in order (first match wins)
        for rule in &self.compiled_rules {
            if self.rule_matches(rule, &parsed, identity) {
                let allowed = matches!(rule.effect, Effect::Allow);
                return EvaluationResult {
                    allowed,
                    matched_rule: Some(rule.id.clone()),
                    reason: if !allowed { rule.reason.clone() } else { None },
                    audit_mode: self.policy.mode == PolicyMode::Audit,
                };
            }
        }

        // No rule matched, use default action
        let allowed = matches!(self.policy.default, DefaultAction::Allow);
        EvaluationResult {
            allowed,
            matched_rule: None,
            reason: if !allowed { Some("No matching rule, default policy is deny".to_string()) } else { None },
            audit_mode: self.policy.mode == PolicyMode::Audit,
        }
    }

    /// Get rate limit configuration
    pub fn rate_limit_config(&self) -> &RateLimitConfig {
        &self.policy.rate_limit
    }

    /// Check if a compiled rule matches the parsed command
    fn rule_matches(&self, rule: &CompiledRule, cmd: &ParsedCommand, identity: Option<&str>) -> bool {
        // If identity pattern is specified, it must match
        if let Some(ref pattern) = rule.identity_pattern {
            match identity {
                Some(id) if pattern.is_match(id) => {}
                _ => return false,
            }
        }

        // If executable pattern is specified, it must match
        if let Some(ref pattern) = rule.executable_pattern {
            if !pattern.is_match(&cmd.executable) {
                return false;
            }
        }

        // If args pattern is specified, it must match
        if let Some(ref pattern) = rule.args_pattern {
            // Check against args string
            if !pattern.is_match(&cmd.args_string) {
                // Also check against full command for patterns that don't care about executable
                if rule.executable_pattern.is_none() && !pattern.is_match(&cmd.raw) {
                    return false;
                } else if rule.executable_pattern.is_some() {
                    return false;
                }
            }
        }

        // If we have no patterns at all (except identity), the rule doesn't match anything specific
        if rule.executable_pattern.is_none() && rule.args_pattern.is_none() && rule.identity_pattern.is_none() {
            return false;
        }

        true
    }

    /// Get policy info for display
    pub fn info(&self) -> String {
        format!(
            "Policy v{} | Mode: {:?} | Default: {:?} | Rules: {}",
            self.policy.version,
            self.policy.mode,
            self.policy.default,
            self.compiled_rules.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> &'static str {
        r#"
version: "1.0"
mode: enforce
default: deny

rules:
  - id: allow_ls
    match:
      executable: "^ls$"
    effect: allow

  - id: block_sudo
    match:
      executable: "^sudo$"
    effect: deny
    reason: "Privilege escalation blocked"

  - id: git_read_only
    match:
      executable: "^git$"
      args_pattern: "^(status|log|diff)"
    effect: allow

  - id: git_block_push
    match:
      executable: "^git$"
      args_pattern: "^push"
    effect: deny
    reason: "Git push is blocked"
"#
    }

    #[test]
    fn test_load_policy() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        assert_eq!(engine.policy.mode, PolicyMode::Enforce);
        assert_eq!(engine.policy.default, DefaultAction::Deny);
        assert_eq!(engine.compiled_rules.len(), 4);
    }

    #[test]
    fn test_allow_ls() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        let result = engine.evaluate("ls -la");
        assert!(result.allowed);
        assert_eq!(result.matched_rule, Some("allow_ls".to_string()));
    }

    #[test]
    fn test_block_sudo() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        let result = engine.evaluate("sudo rm -rf /");
        assert!(!result.allowed);
        assert_eq!(result.matched_rule, Some("block_sudo".to_string()));
        assert_eq!(result.reason, Some("Privilege escalation blocked".to_string()));
    }

    #[test]
    fn test_git_status_allowed() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        let result = engine.evaluate("git status");
        assert!(result.allowed);
        assert_eq!(result.matched_rule, Some("git_read_only".to_string()));
    }

    #[test]
    fn test_git_push_blocked() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        let result = engine.evaluate("git push origin main");
        assert!(!result.allowed);
        assert_eq!(result.matched_rule, Some("git_block_push".to_string()));
    }

    #[test]
    fn test_unknown_command_denied() {
        let engine = PolicyEngine::load_from_string(test_policy()).unwrap();
        let result = engine.evaluate("unknown_command --flag");
        assert!(!result.allowed);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn test_parse_command() {
        let cmd = ParsedCommand::parse("git push origin main");
        assert_eq!(cmd.executable, "git");
        assert_eq!(cmd.args_string, "push origin main");

        let cmd2 = ParsedCommand::parse("/usr/bin/ls -la");
        assert_eq!(cmd2.executable, "ls");
        assert_eq!(cmd2.args_string, "-la");
    }
}
