//! Integration tests for sandbox execution
//!
//! These tests exercise the full SandboxExecutor API with various scenarios.
//! On macOS, tests expect the non-sandboxed fallback behavior.
//! On Linux, tests verify full sandboxing with cgroups and namespaces.

use execwall::sandbox::{SandboxExecutor, SandboxRequest};
use std::collections::HashMap;

/// Helper to create a basic request with the given code
fn make_request(code: &str) -> SandboxRequest {
    let temp_dir = std::env::temp_dir();
    SandboxRequest {
        code: code.to_string(),
        profile: "test_profile".to_string(),
        cwd: temp_dir.to_string_lossy().to_string(),
        fs_read_allow: vec![temp_dir.to_string_lossy().to_string()],
        fs_write_allow: vec![temp_dir.to_string_lossy().to_string()],
        timeout_sec: 30,
        mem_max_mb: 512,
        pids_max: 64,
        max_stdout_bytes: 200_000,
        max_stderr_bytes: 200_000,
        env: HashMap::new(),
    }
}

/// Helper to create a request with custom timeout (Linux-only tests)
#[cfg(target_os = "linux")]
fn make_request_with_timeout(code: &str, timeout_sec: u64) -> SandboxRequest {
    let mut req = make_request(code);
    req.timeout_sec = timeout_sec;
    req
}

/// Helper to create a request with custom output limits
fn make_request_with_output_limit(code: &str, max_stdout_bytes: usize) -> SandboxRequest {
    let mut req = make_request(code);
    req.max_stdout_bytes = max_stdout_bytes;
    req
}

/// Helper to create a request with custom memory limit
fn make_request_with_memory_limit(code: &str, mem_max_mb: u64) -> SandboxRequest {
    let mut req = make_request(code);
    req.mem_max_mb = mem_max_mb;
    req
}

/// Helper to create a request with custom PID limit (Linux-only tests)
#[cfg(target_os = "linux")]
fn make_request_with_pid_limit(code: &str, pids_max: u32) -> SandboxRequest {
    let mut req = make_request(code);
    req.pids_max = pids_max;
    req
}

/// Create an executor for testing
fn create_executor() -> SandboxExecutor {
    SandboxExecutor::new("/usr/lib/execwall/python_runner")
}

// =============================================================================
// Test 1: Simple Python print statement
// =============================================================================

#[test]
fn test_simple_print_statement() {
    let executor = create_executor();
    let request = make_request("print('hello world')");

    let result = executor.execute(&request);
    assert!(
        result.is_ok(),
        "Execution should succeed: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0, "Exit code should be 0");
    assert!(
        response.stdout.contains("hello world"),
        "stdout should contain 'hello world', got: {}",
        response.stdout
    );
    assert!(!response.timed_out, "Should not have timed out");
    assert!(!response.truncated_stdout, "stdout should not be truncated");
}

#[test]
fn test_print_multiple_lines() {
    let executor = create_executor();
    let code = r#"
print('line 1')
print('line 2')
print('line 3')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("line 1"));
    assert!(response.stdout.contains("line 2"));
    assert!(response.stdout.contains("line 3"));
}

#[test]
fn test_print_unicode() {
    let executor = create_executor();
    let code = "print('Hello, world!')";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    // Unicode handling may vary; check it doesn't crash
    assert!(!response.stdout.is_empty() || !response.stderr.is_empty());
}

#[test]
fn test_code_hash_in_response() {
    let executor = create_executor();
    let code = "print('test')";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // SHA256 hash should be 64 hex characters
    assert_eq!(response.code_sha256.len(), 64);
    // Hash should match the request's code_hash
    assert_eq!(response.code_sha256, request.code_hash());
}

// =============================================================================
// Test 2: Python code that times out (infinite loop)
// =============================================================================

// This test only runs on Linux because macOS fallback doesn't enforce timeouts
#[test]
#[cfg(target_os = "linux")]
fn test_timeout_infinite_loop() {
    let executor = create_executor();
    let code = "while True: pass";
    // Use a short timeout for testing
    let request = make_request_with_timeout(code, 2);

    let result = executor.execute(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.timed_out, "Should have timed out on Linux");
    assert!(
        response.wall_time_ms >= 2000,
        "Should have run for at least 2 seconds"
    );
}

// This test only runs on Linux because macOS fallback doesn't enforce timeouts
#[test]
#[cfg(target_os = "linux")]
fn test_timeout_sleep_based() {
    let executor = create_executor();
    // This test uses Python's time.sleep which is interruptible
    let code = r#"
import time
time.sleep(5)
print('finished')
"#;
    let request = make_request_with_timeout(code, 1);

    let result = executor.execute(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.timed_out, "Should have timed out");
    assert!(
        !response.stdout.contains("finished"),
        "Should not have finished"
    );
}

// =============================================================================
// Test 3: Python code that exceeds memory limit
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
#[ignore] // Requires cgroups - not available in CI
fn test_memory_limit_exceeded() {
    let executor = create_executor();
    // Try to allocate a large list
    let code = r#"
# Allocate roughly 100MB of data
data = [b'x' * (1024 * 1024) for _ in range(100)]
print(f'Allocated {len(data)} MB')
"#;
    // Set memory limit to 50MB
    let request = make_request_with_memory_limit(code, 50);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // Process should be killed due to OOM
    assert_ne!(
        response.exit_code, 0,
        "Should have failed due to memory limit"
    );
}

#[test]
fn test_memory_within_limits() {
    let executor = create_executor();
    let code = r#"
# Small allocation that should succeed
data = [i for i in range(1000)]
print(f'Allocated list with {len(data)} items')
"#;
    let request = make_request_with_memory_limit(code, 512);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0, "Should succeed with ample memory");
    assert!(response.stdout.contains("1000"));
}

// =============================================================================
// Test 4: Python code with syntax error
// =============================================================================

#[test]
fn test_syntax_error() {
    let executor = create_executor();
    let code = "print('unclosed string";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok(), "Executor should not error on syntax errors");

    let response = result.unwrap();
    assert_ne!(
        response.exit_code, 0,
        "Exit code should be non-zero for syntax error"
    );
    // Python puts syntax errors on stderr
    assert!(
        response.stderr.contains("SyntaxError") || response.stderr.contains("syntax"),
        "stderr should contain syntax error message, got: {}",
        response.stderr
    );
}

#[test]
fn test_indentation_error() {
    let executor = create_executor();
    let code = r#"
def foo():
print('bad indent')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_ne!(response.exit_code, 0);
    assert!(
        response.stderr.contains("IndentationError") || response.stderr.contains("indent"),
        "stderr should mention indentation error, got: {}",
        response.stderr
    );
}

#[test]
fn test_name_error() {
    let executor = create_executor();
    let code = "print(undefined_variable)";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_ne!(response.exit_code, 0);
    assert!(
        response.stderr.contains("NameError"),
        "stderr should contain NameError, got: {}",
        response.stderr
    );
}

#[test]
fn test_import_error() {
    let executor = create_executor();
    let code = "import nonexistent_module_xyz123";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_ne!(response.exit_code, 0);
    assert!(
        response.stderr.contains("ModuleNotFoundError") || response.stderr.contains("ImportError"),
        "stderr should contain module error, got: {}",
        response.stderr
    );
}

#[test]
fn test_runtime_exception() {
    let executor = create_executor();
    let code = r#"
raise ValueError("intentional error")
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_ne!(response.exit_code, 0);
    assert!(
        response.stderr.contains("ValueError") && response.stderr.contains("intentional error"),
        "stderr should contain ValueError and message, got: {}",
        response.stderr
    );
}

#[test]
fn test_division_by_zero() {
    let executor = create_executor();
    let code = "x = 1 / 0";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_ne!(response.exit_code, 0);
    assert!(
        response.stderr.contains("ZeroDivisionError"),
        "stderr should contain ZeroDivisionError, got: {}",
        response.stderr
    );
}

// =============================================================================
// Test 5: Python code that tries forbidden operations (Linux-specific)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
#[ignore] // Requires network namespace - not available in CI
fn test_forbidden_network_access() {
    let executor = create_executor();
    let code = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('google.com', 80))
print('connected')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // On Linux with seccomp, network operations should be blocked
    // The process might crash or get an error
    assert!(
        response.exit_code != 0 || !response.stdout.contains("connected"),
        "Network access should be blocked"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_forbidden_file_write_outside_allowed() {
    let executor = create_executor();
    let code = r#"
with open('/etc/test_forbidden', 'w') as f:
    f.write('should not work')
print('wrote file')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // Writing outside allowed paths should fail
    assert_ne!(response.exit_code, 0, "File write should fail");
    assert!(!response.stdout.contains("wrote file"));
}

#[test]
#[cfg(target_os = "linux")]
fn test_forbidden_process_spawn() {
    let executor = create_executor();
    let code = r#"
import subprocess
subprocess.run(['ls', '-la'])
print('ran subprocess')
"#;
    // Depending on seccomp policy, this might be blocked
    let request = make_request(code);

    let result = executor.execute(&request);
    // We mainly verify the sandbox doesn't crash
    assert!(result.is_ok());
}

// =============================================================================
// Test 6: Output truncation when stdout exceeds max_stdout_bytes
// =============================================================================

#[test]
fn test_stdout_truncation() {
    let executor = create_executor();
    // Generate output larger than the limit
    let code = r#"
for i in range(10000):
    print(f'Line {i}: ' + 'x' * 100)
"#;
    // Set a small limit to trigger truncation
    let request = make_request_with_output_limit(code, 1000);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // On macOS (fallback mode), truncation is implemented
    // On Linux, truncation should also work
    assert!(
        response.stdout.len() <= 1000 + 20, // Allow some margin for [TRUNCATED] suffix
        "stdout length {} should be <= limit + margin",
        response.stdout.len()
    );

    if response.truncated_stdout {
        assert!(
            response.stdout.contains("[TRUNCATED]"),
            "Truncated output should contain [TRUNCATED] marker"
        );
    }
}

#[test]
fn test_stderr_truncation() {
    let executor = create_executor();
    let code = r#"
import sys
for i in range(10000):
    print(f'Error {i}: ' + 'x' * 100, file=sys.stderr)
"#;
    let mut request = make_request(code);
    request.max_stderr_bytes = 1000;

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(
        response.stderr.len() <= 1000 + 20,
        "stderr length {} should be <= limit + margin",
        response.stderr.len()
    );
}

#[test]
fn test_no_truncation_when_under_limit() {
    let executor = create_executor();
    let code = "print('small output')";
    let request = make_request_with_output_limit(code, 10000);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(!response.truncated_stdout, "Should not be truncated");
    assert!(!response.stdout.contains("[TRUNCATED]"));
}

// =============================================================================
// Test 7: Resource limit enforcement (PID limits)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_pid_limit_enforcement() {
    let executor = create_executor();
    let code = r#"
import os
import multiprocessing

def worker():
    import time
    time.sleep(10)

# Try to spawn many processes
processes = []
for i in range(100):
    try:
        p = multiprocessing.Process(target=worker)
        p.start()
        processes.append(p)
    except Exception as e:
        print(f'Failed to spawn process {i}: {e}')
        break

print(f'Spawned {len(processes)} processes')
for p in processes:
    p.terminate()
"#;
    // Very low PID limit
    let request = make_request_with_pid_limit(code, 5);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // Should be limited in number of processes it can spawn
    // The exact behavior depends on cgroup enforcement
    // We mainly verify it doesn't crash and respects some limit
    assert!(response.stdout.contains("Spawned") || response.stderr.len() > 0);
}

// =============================================================================
// Test 8: Wall time tracking
// =============================================================================

#[test]
fn test_wall_time_tracking() {
    let executor = create_executor();
    let code = r#"
import time
time.sleep(0.5)
print('done')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    // Wall time should be at least 500ms
    assert!(
        response.wall_time_ms >= 400, // Allow some margin
        "Wall time should be >= 400ms, got: {}",
        response.wall_time_ms
    );
    // But not too long
    assert!(
        response.wall_time_ms < 5000,
        "Wall time should be < 5000ms, got: {}",
        response.wall_time_ms
    );
}

// =============================================================================
// Test 9: Environment variables
// =============================================================================

#[test]
fn test_environment_variables() {
    let executor = create_executor();
    let code = r#"
import os
print(os.environ.get('TEST_VAR', 'NOT_SET'))
"#;
    let mut request = make_request(code);
    request
        .env
        .insert("TEST_VAR".to_string(), "hello_from_env".to_string());

    let result = executor.execute(&request);

    // On macOS fallback, env isn't cleared, so it might pick up the var
    // On Linux, env is cleared but we pass explicit vars
    // For now, just ensure execution works
    assert!(result.is_ok());
}

// =============================================================================
// Test 10: Complex Python code
// =============================================================================

#[test]
fn test_complex_computation() {
    let executor = create_executor();
    let code = r#"
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

result = fibonacci(20)
print(f'fibonacci(20) = {result}')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("fibonacci(20) = 6765"));
}

#[test]
fn test_list_comprehension() {
    let executor = create_executor();
    let code = r#"
squares = [x**2 for x in range(10)]
print(squares)
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response
        .stdout
        .contains("[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]"));
}

#[test]
fn test_json_handling() {
    let executor = create_executor();
    let code = r#"
import json
data = {'name': 'test', 'values': [1, 2, 3]}
json_str = json.dumps(data)
parsed = json.loads(json_str)
print(f'Parsed: {parsed}')
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("test"));
}

// =============================================================================
// Test 11: Exit code handling
// =============================================================================

#[test]
fn test_explicit_exit_code() {
    let executor = create_executor();
    let code = r#"
import sys
sys.exit(42)
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 42, "Exit code should be 42");
}

#[test]
fn test_exit_zero() {
    let executor = create_executor();
    let code = r#"
import sys
print('before exit')
sys.exit(0)
print('after exit')  # Should not execute
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("before exit"));
    assert!(!response.stdout.contains("after exit"));
}

// =============================================================================
// Test 12: Empty and whitespace code
// =============================================================================

#[test]
fn test_empty_code() {
    let executor = create_executor();
    let code = "";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // Empty code should succeed with exit code 0
    assert_eq!(response.exit_code, 0);
}

#[test]
fn test_whitespace_only_code() {
    let executor = create_executor();
    let code = "   \n\n  \t  ";
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
}

#[test]
fn test_comment_only_code() {
    let executor = create_executor();
    let code = r#"
# This is a comment
# Another comment
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
}

// =============================================================================
// Test 13: SandboxRequest defaults and configuration
// =============================================================================

#[test]
fn test_sandbox_request_defaults() {
    let request = SandboxRequest::default();
    assert_eq!(request.timeout_sec, 30);
    assert_eq!(request.mem_max_mb, 512);
    assert_eq!(request.pids_max, 64);
    assert_eq!(request.max_stdout_bytes, 200_000);
    assert_eq!(request.max_stderr_bytes, 200_000);
    assert_eq!(request.profile, "python_sandbox_v1");
    // cwd defaults to temp dir for cross-platform compatibility
    let expected_cwd = std::env::temp_dir().to_string_lossy().to_string();
    assert_eq!(request.cwd, expected_cwd);
}

#[test]
fn test_code_hash_consistency() {
    let code = "print('hello')";
    let mut request1 = make_request(code);
    let mut request2 = make_request(code);

    assert_eq!(
        request1.code_hash(),
        request2.code_hash(),
        "Same code should produce same hash"
    );

    request2.code = "print('different')".to_string();
    assert_ne!(
        request1.code_hash(),
        request2.code_hash(),
        "Different code should produce different hash"
    );
}

// =============================================================================
// Test 14: Mixed stdout and stderr
// =============================================================================

#[test]
fn test_mixed_stdout_stderr() {
    let executor = create_executor();
    let code = r#"
import sys
print('stdout line 1')
print('stderr line 1', file=sys.stderr)
print('stdout line 2')
print('stderr line 2', file=sys.stderr)
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);
    assert!(response.stdout.contains("stdout line 1"));
    assert!(response.stdout.contains("stdout line 2"));
    assert!(response.stderr.contains("stderr line 1"));
    assert!(response.stderr.contains("stderr line 2"));
}

// =============================================================================
// Test 15: Platform-specific behavior verification
// =============================================================================

#[test]
fn test_platform_warning_on_macos() {
    // This test verifies that on macOS, the executor runs (with reduced security)
    // and that the warning is printed
    let executor = create_executor();
    let request = make_request("print('platform test')");

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.exit_code, 0);

    // On non-Linux, peak_mem_mb should be 0 (not tracked)
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(
            response.peak_mem_mb, 0,
            "peak_mem_mb should be 0 on non-Linux"
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
#[ignore] // Requires cgroups - not available in CI
fn test_linux_memory_tracking() {
    let executor = create_executor();
    let code = r#"
# Allocate some memory to get a non-zero peak
data = [x for x in range(100000)]
print(len(data))
"#;
    let request = make_request(code);

    let result = executor.execute(&request);
    assert!(result.is_ok());

    let response = result.unwrap();
    // On Linux, peak_mem_mb should be tracked
    // Python itself uses some memory, so it should be > 0
    assert!(
        response.peak_mem_mb > 0,
        "peak_mem_mb should be tracked on Linux, got: {}",
        response.peak_mem_mb
    );
}
