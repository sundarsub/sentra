# Claude Agent SDK + Execwall Secure Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a split-plane secure agent architecture where Claude Agent SDK (Planner) executes commands exclusively through Execwall (Executor) using CLI tools with JSON-in/JSON-out interfaces.

**Architecture:** Split-plane model with network-isolated Planner running Claude Agent SDK that can only call `execwall_run`. Executor plane runs Execwall with seccomp/namespaces/cgroups. All external capabilities are single-purpose CLI tools with strict JSON schemas, governed by deny-by-default YAML policy.

**Tech Stack:** Rust (execwall core), Python (Claude Agent SDK, CLI tools), YAML (policy), JSON (schemas), seccomp-BPF (syscall filtering)

---

## Phase 1: CLI Tool Infrastructure

### Task 1: Create CLI Tool Framework

**Files:**
- Create: `tools/lib/tool_base.py`
- Create: `tools/lib/__init__.py`
- Test: `tools/tests/test_tool_base.py`

**Step 1: Write the failing test**

```python
# tools/tests/test_tool_base.py
import pytest
import json
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

def test_tool_base_validates_input():
    """Tool base should validate JSON input against schema."""
    class EchoTool(ToolBase):
        INPUT_SCHEMA = {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"]
        }

        def execute(self, request: ToolRequest) -> ToolResponse:
            return ToolResponse(success=True, data={"echo": request.params["message"]})

    tool = EchoTool()
    result = tool.run('{"message": "hello"}')
    assert result["success"] is True
    assert result["data"]["echo"] == "hello"

def test_tool_base_rejects_invalid_input():
    """Tool base should reject input that doesn't match schema."""
    class EchoTool(ToolBase):
        INPUT_SCHEMA = {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"]
        }

        def execute(self, request: ToolRequest) -> ToolResponse:
            return ToolResponse(success=True, data={})

    tool = EchoTool()
    result = tool.run('{"wrong_field": "hello"}')
    assert result["success"] is False
    assert "validation" in result["error"].lower()

def test_tool_response_has_deterministic_structure():
    """Tool responses must have consistent structure."""
    class SimpleTool(ToolBase):
        INPUT_SCHEMA = {"type": "object"}
        def execute(self, request: ToolRequest) -> ToolResponse:
            return ToolResponse(success=True, data={"result": 42})

    tool = SimpleTool()
    result = tool.run('{}')
    assert "success" in result
    assert "data" in result
    assert "exit_code" in result
    assert result["exit_code"] == 0
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_tool_base.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# tools/lib/__init__.py
from .tool_base import ToolBase, ToolRequest, ToolResponse

__all__ = ["ToolBase", "ToolRequest", "ToolResponse"]
```

```python
# tools/lib/tool_base.py
"""Base class for all CLI tools with JSON-in/JSON-out interface."""
import json
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import jsonschema

@dataclass
class ToolRequest:
    """Validated input request."""
    params: Dict[str, Any]
    raw_input: str

@dataclass
class ToolResponse:
    """Structured tool response."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    exit_code: int = 0

    def __post_init__(self):
        if not self.success and self.exit_code == 0:
            self.exit_code = 1

class ToolBase(ABC):
    """Abstract base for all CLI tools."""

    INPUT_SCHEMA: Dict[str, Any] = {"type": "object"}
    OUTPUT_SCHEMA: Dict[str, Any] = {"type": "object"}

    @abstractmethod
    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute the tool with validated request."""
        pass

    def validate_input(self, json_str: str) -> tuple[bool, Optional[Dict], Optional[str]]:
        """Validate JSON input against schema."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            return False, None, f"JSON parse error: {e}"

        try:
            jsonschema.validate(instance=data, schema=self.INPUT_SCHEMA)
        except jsonschema.ValidationError as e:
            return False, None, f"Validation error: {e.message}"

        return True, data, None

    def run(self, json_input: str) -> Dict[str, Any]:
        """Run tool with JSON input, return JSON-serializable dict."""
        valid, data, error = self.validate_input(json_input)

        if not valid:
            return {
                "success": False,
                "data": {},
                "error": error,
                "exit_code": 2
            }

        try:
            request = ToolRequest(params=data, raw_input=json_input)
            response = self.execute(request)
            return {
                "success": response.success,
                "data": response.data,
                "error": response.error,
                "exit_code": response.exit_code
            }
        except Exception as e:
            return {
                "success": False,
                "data": {},
                "error": f"Execution error: {str(e)}",
                "exit_code": 1
            }

    def main(self):
        """CLI entry point: reads JSON from stdin or --json arg."""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--json", "-j", help="JSON input (or use stdin)")
        args = parser.parse_args()

        if args.json:
            if args.json.startswith("@"):
                with open(args.json[1:], "r") as f:
                    json_input = f.read()
            else:
                json_input = args.json
        else:
            json_input = sys.stdin.read()

        result = self.run(json_input)
        print(json.dumps(result, indent=2))
        sys.exit(result["exit_code"])
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_tool_base.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add tools/
git commit -m "feat: add CLI tool base framework with JSON schema validation"
```

---

### Task 2: Create Calendar Read Tool

**Files:**
- Create: `tools/cal_read.py`
- Test: `tools/tests/test_cal_read.py`

**Step 1: Write the failing test**

```python
# tools/tests/test_cal_read.py
import pytest
import json
from unittest.mock import patch, MagicMock
from cal_read import CalendarReadTool

def test_cal_read_returns_events():
    """cal_read should return events from Google Calendar."""
    tool = CalendarReadTool()

    mock_events = [
        {"id": "1", "summary": "Meeting", "start": "2026-02-28T10:00:00Z"},
        {"id": "2", "summary": "Lunch", "start": "2026-02-28T12:00:00Z"}
    ]

    with patch.object(tool, '_fetch_events', return_value=mock_events):
        result = tool.run('{"date": "2026-02-28", "max_results": 10}')

    assert result["success"] is True
    assert len(result["data"]["events"]) == 2
    assert result["data"]["events"][0]["summary"] == "Meeting"

def test_cal_read_validates_date_format():
    """cal_read should reject invalid date formats."""
    tool = CalendarReadTool()
    result = tool.run('{"date": "not-a-date"}')

    assert result["success"] is False
    assert "validation" in result["error"].lower() or "date" in result["error"].lower()

def test_cal_read_has_correct_schema():
    """cal_read should have proper input schema."""
    tool = CalendarReadTool()
    assert "date" in tool.INPUT_SCHEMA["properties"]
    assert tool.INPUT_SCHEMA["required"] == ["date"]
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_cal_read.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
# tools/cal_read.py
"""Read-only Google Calendar tool with JSON interface."""
import os
import re
from datetime import datetime
from typing import Any, Dict, List
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class CalendarReadTool(ToolBase):
    """Fetch calendar events (read-only)."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "date": {
                "type": "string",
                "pattern": r"^\d{4}-\d{2}-\d{2}$",
                "description": "Date in YYYY-MM-DD format"
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 10
            },
            "calendar_id": {
                "type": "string",
                "default": "primary"
            }
        },
        "required": ["date"]
    }

    OUTPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "summary": {"type": "string"},
                        "start": {"type": "string"},
                        "end": {"type": "string"},
                        "location": {"type": "string"}
                    }
                }
            },
            "count": {"type": "integer"}
        }
    }

    def validate_input(self, json_str: str) -> tuple[bool, Dict | None, str | None]:
        """Extended validation for date format."""
        valid, data, error = super().validate_input(json_str)
        if not valid:
            return valid, data, error

        # Additional date validation
        date_str = data.get("date", "")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
            return False, None, "Validation error: date must be YYYY-MM-DD format"

        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return False, None, "Validation error: invalid date"

        return True, data, None

    def _fetch_events(self, date: str, max_results: int, calendar_id: str) -> List[Dict]:
        """Fetch events from Google Calendar API via gcal CLI."""
        import subprocess
        import json

        result = subprocess.run(
            [os.path.expanduser("~/.local/bin/gcal"), "list", "--date", date, "--json"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError(f"gcal failed: {result.stderr}")

        events = json.loads(result.stdout)
        return events[:max_results]

    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute calendar read."""
        try:
            events = self._fetch_events(
                date=request.params["date"],
                max_results=request.params.get("max_results", 10),
                calendar_id=request.params.get("calendar_id", "primary")
            )

            return ToolResponse(
                success=True,
                data={
                    "events": events,
                    "count": len(events)
                }
            )
        except Exception as e:
            return ToolResponse(
                success=False,
                error=str(e)
            )

if __name__ == "__main__":
    CalendarReadTool().main()
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_cal_read.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add tools/cal_read.py tools/tests/test_cal_read.py
git commit -m "feat: add cal_read CLI tool with JSON interface"
```

---

### Task 3: Create Calendar Write Tool (High Privilege)

**Files:**
- Create: `tools/cal_create.py`
- Test: `tools/tests/test_cal_create.py`

**Step 1: Write the failing test**

```python
# tools/tests/test_cal_create.py
import pytest
from unittest.mock import patch
from cal_create import CalendarCreateTool

def test_cal_create_requires_approval_token():
    """cal_create should require approval token for write operations."""
    tool = CalendarCreateTool()

    result = tool.run('''{
        "summary": "New Meeting",
        "start": "2026-02-28T14:00:00Z",
        "end": "2026-02-28T15:00:00Z"
    }''')

    # Without approval token, should fail
    assert result["success"] is False
    assert "approval" in result["error"].lower() or "token" in result["error"].lower()

def test_cal_create_succeeds_with_valid_token():
    """cal_create should succeed with valid approval token."""
    tool = CalendarCreateTool()

    with patch.object(tool, '_validate_approval_token', return_value=True):
        with patch.object(tool, '_create_event', return_value={"id": "evt123"}):
            result = tool.run('''{
                "summary": "New Meeting",
                "start": "2026-02-28T14:00:00Z",
                "end": "2026-02-28T15:00:00Z",
                "approval_token": "valid-token-123"
            }''')

    assert result["success"] is True
    assert result["data"]["event_id"] == "evt123"

def test_cal_create_validates_time_range():
    """cal_create should reject end time before start time."""
    tool = CalendarCreateTool()

    with patch.object(tool, '_validate_approval_token', return_value=True):
        result = tool.run('''{
            "summary": "Invalid Meeting",
            "start": "2026-02-28T15:00:00Z",
            "end": "2026-02-28T14:00:00Z",
            "approval_token": "valid-token"
        }''')

    assert result["success"] is False
    assert "end" in result["error"].lower() or "time" in result["error"].lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_cal_create.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
# tools/cal_create.py
"""Write Google Calendar events (high privilege, requires approval)."""
import os
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class CalendarCreateTool(ToolBase):
    """Create calendar events (requires approval token)."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 500},
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
            "location": {"type": "string", "maxLength": 500},
            "description": {"type": "string", "maxLength": 5000},
            "attendees": {
                "type": "array",
                "items": {"type": "string", "format": "email"},
                "maxItems": 50
            },
            "approval_token": {"type": "string"},
            "calendar_id": {"type": "string", "default": "primary"}
        },
        "required": ["summary", "start", "end"]
    }

    def _validate_approval_token(self, token: str, action_hash: str) -> bool:
        """Validate approval token from gatekeeper."""
        # Token format: HMAC-SHA256(secret, action_hash + timestamp)
        # In production, verify against gatekeeper service
        secret = os.environ.get("EXECWALL_APPROVAL_SECRET", "")
        if not secret:
            return False

        # For now, simple validation - production would check expiry
        expected = hmac.new(
            secret.encode(),
            action_hash.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        return hmac.compare_digest(token, expected)

    def _create_event(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create event via gcal CLI."""
        import subprocess
        import json

        cmd = [
            os.path.expanduser("~/.local/bin/gcal"), "add",
            "--summary", params["summary"],
            "--start", params["start"],
            "--end", params["end"],
            "--json"
        ]

        if params.get("location"):
            cmd.extend(["--location", params["location"]])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            raise RuntimeError(f"gcal add failed: {result.stderr}")

        return json.loads(result.stdout)

    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute calendar event creation."""
        params = request.params

        # Require approval token for write operations
        token = params.get("approval_token")
        if not token:
            return ToolResponse(
                success=False,
                error="Approval token required for calendar write operations",
                exit_code=3
            )

        # Validate time range
        try:
            start = datetime.fromisoformat(params["start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(params["end"].replace("Z", "+00:00"))
            if end <= start:
                return ToolResponse(
                    success=False,
                    error="End time must be after start time"
                )
        except ValueError as e:
            return ToolResponse(
                success=False,
                error=f"Invalid datetime format: {e}"
            )

        # Compute action hash for token validation
        action_hash = hashlib.sha256(
            f"cal_create:{params['summary']}:{params['start']}".encode()
        ).hexdigest()

        if not self._validate_approval_token(token, action_hash):
            return ToolResponse(
                success=False,
                error="Invalid or expired approval token",
                exit_code=3
            )

        try:
            result = self._create_event(params)
            return ToolResponse(
                success=True,
                data={
                    "event_id": result.get("id"),
                    "link": result.get("htmlLink"),
                    "created": True
                }
            )
        except Exception as e:
            return ToolResponse(
                success=False,
                error=str(e)
            )

if __name__ == "__main__":
    CalendarCreateTool().main()
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_cal_create.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add tools/cal_create.py tools/tests/test_cal_create.py
git commit -m "feat: add cal_create CLI tool with approval token requirement"
```

---

### Task 4: Create Web Search Tool

**Files:**
- Create: `tools/web_search.py`
- Test: `tools/tests/test_web_search.py`

**Step 1: Write the failing test**

```python
# tools/tests/test_web_search.py
import pytest
from unittest.mock import patch
from web_search import WebSearchTool

def test_web_search_returns_results():
    """web_search should return search results."""
    tool = WebSearchTool()

    mock_results = [
        {"title": "Result 1", "url": "https://example.com/1", "snippet": "First result"},
        {"title": "Result 2", "url": "https://example.com/2", "snippet": "Second result"}
    ]

    with patch.object(tool, '_search', return_value=mock_results):
        result = tool.run('{"query": "test query", "max_results": 5}')

    assert result["success"] is True
    assert len(result["data"]["results"]) == 2

def test_web_search_requires_query():
    """web_search should require query parameter."""
    tool = WebSearchTool()
    result = tool.run('{}')

    assert result["success"] is False
    assert "query" in result["error"].lower() or "required" in result["error"].lower()

def test_web_search_limits_results():
    """web_search should respect max_results limit."""
    tool = WebSearchTool()
    assert tool.INPUT_SCHEMA["properties"]["max_results"]["maximum"] == 20
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_web_search.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
# tools/web_search.py
"""Web search tool using Tavily API."""
import os
import subprocess
from typing import Any, Dict, List
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class WebSearchTool(ToolBase):
    """Search the web (read-only, uses Tavily API)."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "minLength": 1,
                "maxLength": 500,
                "description": "Search query"
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "default": 5
            },
            "search_depth": {
                "type": "string",
                "enum": ["basic", "advanced"],
                "default": "basic"
            }
        },
        "required": ["query"]
    }

    def _search(self, query: str, max_results: int) -> List[Dict]:
        """Execute search via websearch CLI."""
        result = subprocess.run(
            [os.path.expanduser("~/.local/bin/websearch"), query, "--json"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError(f"websearch failed: {result.stderr}")

        import json
        results = json.loads(result.stdout)
        return results[:max_results]

    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute web search."""
        try:
            results = self._search(
                query=request.params["query"],
                max_results=request.params.get("max_results", 5)
            )

            return ToolResponse(
                success=True,
                data={
                    "results": results,
                    "count": len(results),
                    "query": request.params["query"]
                }
            )
        except Exception as e:
            return ToolResponse(
                success=False,
                error=str(e)
            )

if __name__ == "__main__":
    WebSearchTool().main()
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest tools/tests/test_web_search.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add tools/web_search.py tools/tests/test_web_search.py
git commit -m "feat: add web_search CLI tool"
```

---

## Phase 2: Execwall Policy Profiles

### Task 5: Create Deny-by-Default Policy Structure

**Files:**
- Modify: `policy.yaml` (create new version)
- Create: `policy-agent.yaml`
- Test: Manual validation with execwall

**Step 1: Create policy structure**

```yaml
# policy-agent.yaml
# Deny-by-default policy for Claude Agent SDK integration
version: "2.0"
mode: enforce

# Global defaults
defaults:
  effect: deny
  audit: true
  rate_limit:
    requests_per_minute: 60
    burst: 10

# Named profiles for different privilege levels
profiles:
  # Read-only tools - minimal privileges
  tools_readonly:
    description: "Read-only tool execution"
    runner: null  # Direct execution
    network:
      allow: false
      proxy: "http://localhost:8080"  # Optional egress proxy
    filesystem:
      read_allow:
        - "/work/in"
        - "/tmp/tool_cache"
      write_allow:
        - "/work/out"
      deny:
        - "/etc"
        - "/home"
        - "/root"
    limits:
      timeout_sec: 30
      mem_max_mb: 256
      pids_max: 16
      cpu_percent: 50
    env_inject:
      TOOL_MODE: "readonly"

  # Write tools - higher privilege, requires approval
  tools_write:
    description: "Write operations requiring approval"
    runner: null
    network:
      allow: true
      domains_allow:
        - "*.googleapis.com"
        - "api.slack.com"
        - "graph.microsoft.com"
    filesystem:
      read_allow:
        - "/work/in"
        - "/work/out"
      write_allow:
        - "/work/out"
    limits:
      timeout_sec: 60
      mem_max_mb: 512
      pids_max: 32
    rate_limit:
      requests_per_minute: 10
      burst: 2
    require_approval: true
    env_inject:
      TOOL_MODE: "write"

  # Browser automation - highest isolation
  browser_automation:
    description: "Headless browser operations"
    runner: "/usr/lib/execwall/browser_runner"
    container: true
    network:
      allow: true
      domains_allow:
        - "*"  # Configured per-request
      upload_deny: true
    filesystem:
      read_allow:
        - "/work/in"
      write_allow:
        - "/work/out/downloads"
    limits:
      timeout_sec: 120
      mem_max_mb: 2048
      pids_max: 64
    rate_limit:
      requests_per_minute: 5

# Tool definitions with profile mappings
tools:
  # Read-only tools
  cal_read:
    path: "/usr/lib/execwall/tools/cal_read.py"
    profile: tools_readonly
    description: "Read calendar events"

  news_search:
    path: "/usr/lib/execwall/tools/web_search.py"
    profile: tools_readonly
    description: "Search news and web"

  ib_status:
    path: "/usr/lib/execwall/tools/ib_status.py"
    profile: tools_readonly
    description: "Check IBKR account status"

  # Write tools (require approval)
  cal_create:
    path: "/usr/lib/execwall/tools/cal_create.py"
    profile: tools_write
    description: "Create calendar events"

  slack_post:
    path: "/usr/lib/execwall/tools/slack_post.py"
    profile: tools_write
    description: "Post to Slack"

  wa_send:
    path: "/usr/lib/execwall/tools/wa_send.py"
    profile: tools_write
    description: "Send WhatsApp message"

  email_send:
    path: "/usr/lib/execwall/tools/email_send.py"
    profile: tools_write
    description: "Send email"

  # Browser tools
  browser_download:
    path: "/usr/lib/execwall/tools/browser_download.py"
    profile: browser_automation
    description: "Download file via browser"

# Syscall profiles (Linux)
seccomp_profiles:
  tool_minimal:
    default: deny
    allow:
      - read
      - write
      - open
      - close
      - stat
      - fstat
      - mmap
      - mprotect
      - munmap
      - brk
      - rt_sigaction
      - rt_sigprocmask
      - ioctl
      - access
      - pipe
      - select
      - sched_yield
      - mremap
      - msync
      - dup
      - dup2
      - nanosleep
      - getpid
      - socket
      - connect
      - sendto
      - recvfrom
      - shutdown
      - getsockname
      - getpeername
      - clone
      - execve
      - exit
      - exit_group
      - wait4
      - kill
      - fcntl
      - flock
      - fsync
      - fdatasync
      - truncate
      - ftruncate
      - getcwd
      - chdir
      - readlink
      - gettimeofday
      - getuid
      - getgid
      - geteuid
      - getegid
      - arch_prctl
      - futex
      - set_tid_address
      - set_robust_list
      - clock_gettime
      - clock_getres
      - pread64
      - pwrite64
      - openat
      - newfstatat
      - getrandom
    deny_always:
      - ptrace
      - mount
      - umount2
      - reboot
      - sethostname
      - setdomainname
      - init_module
      - delete_module
      - kexec_load
      - perf_event_open

# Audit configuration
audit:
  enabled: true
  log_path: "/var/log/execwall/agent-audit.jsonl"
  log_args: true  # Redact secrets
  log_output_size: true
  alerts:
    - type: repeated_denials
      threshold: 5
      window_minutes: 1
    - type: large_output
      threshold_bytes: 10485760  # 10MB
    - type: high_write_frequency
      threshold: 20
      window_minutes: 5
```

**Step 2: Validate policy syntax**

Run: `execwall --validate-policy policy-agent.yaml`
Expected: "Policy valid"

**Step 3: Commit**

```bash
git add policy-agent.yaml
git commit -m "feat: add deny-by-default agent policy with profiles"
```

---

### Task 6: Create Execwall Run Interface (Rust)

**Files:**
- Create: `src/agent_runner.rs`
- Modify: `src/lib.rs`
- Test: `tests/agent_runner_test.rs`

**Step 1: Write the failing test**

```rust
// tests/agent_runner_test.rs
use execwall::agent_runner::{AgentRunner, ToolCall, ToolResult};

#[test]
fn test_agent_runner_executes_readonly_tool() {
    let runner = AgentRunner::new("policy-agent.yaml").unwrap();

    let call = ToolCall {
        tool: "cal_read".to_string(),
        args: serde_json::json!({"date": "2026-02-28"}),
        identity: "test-agent".to_string(),
    };

    let result = runner.execute(call);

    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.allowed);
}

#[test]
fn test_agent_runner_blocks_undefined_tool() {
    let runner = AgentRunner::new("policy-agent.yaml").unwrap();

    let call = ToolCall {
        tool: "undefined_tool".to_string(),
        args: serde_json::json!({}),
        identity: "test-agent".to_string(),
    };

    let result = runner.execute(call);

    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(!result.allowed);
    assert!(result.error.contains("not defined"));
}

#[test]
fn test_agent_runner_requires_approval_for_write_tools() {
    let runner = AgentRunner::new("policy-agent.yaml").unwrap();

    let call = ToolCall {
        tool: "cal_create".to_string(),
        args: serde_json::json!({
            "summary": "Test",
            "start": "2026-02-28T10:00:00Z",
            "end": "2026-02-28T11:00:00Z"
        }),
        identity: "test-agent".to_string(),
    };

    let result = runner.execute(call);

    assert!(result.is_ok());
    let result = result.unwrap();
    // Should require approval token
    assert!(!result.allowed || result.requires_approval);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test agent_runner`
Expected: FAIL with "unresolved import"

**Step 3: Write minimal implementation**

```rust
// src/agent_runner.rs
//! Agent Runner - executes tools through Execwall policy enforcement.

use crate::audit::{AuditLogger, AuditEvent};
use crate::policy::{Policy, PolicyDecision};
use crate::sandbox::SandboxExecutor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Tool call request from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub args: serde_json::Value,
    pub identity: String,
    #[serde(default)]
    pub approval_token: Option<String>,
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub allowed: bool,
    pub success: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub requires_approval: bool,
    pub execution_ms: u64,
    pub profile_used: Option<String>,
}

/// Tool definition from policy
#[derive(Debug, Clone, Deserialize)]
pub struct ToolDefinition {
    pub path: String,
    pub profile: String,
    pub description: Option<String>,
}

/// Profile definition
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileDefinition {
    pub description: Option<String>,
    pub runner: Option<String>,
    #[serde(default)]
    pub require_approval: bool,
    pub limits: Option<ProfileLimits>,
    #[serde(default)]
    pub env_inject: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileLimits {
    pub timeout_sec: Option<u64>,
    pub mem_max_mb: Option<u64>,
    pub pids_max: Option<u32>,
}

/// Agent runner with policy enforcement
pub struct AgentRunner {
    policy_path: String,
    tools: HashMap<String, ToolDefinition>,
    profiles: HashMap<String, ProfileDefinition>,
    audit_logger: AuditLogger,
}

impl AgentRunner {
    /// Create new agent runner from policy file
    pub fn new<P: AsRef<Path>>(policy_path: P) -> Result<Self, String> {
        let policy_str = std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("Failed to read policy: {}", e))?;

        let policy: serde_yaml::Value = serde_yaml::from_str(&policy_str)
            .map_err(|e| format!("Failed to parse policy: {}", e))?;

        // Extract tools
        let tools: HashMap<String, ToolDefinition> = policy
            .get("tools")
            .and_then(|t| serde_yaml::from_value(t.clone()).ok())
            .unwrap_or_default();

        // Extract profiles
        let profiles: HashMap<String, ProfileDefinition> = policy
            .get("profiles")
            .and_then(|p| serde_yaml::from_value(p.clone()).ok())
            .unwrap_or_default();

        let audit_logger = AuditLogger::new(
            policy.get("audit")
                .and_then(|a| a.get("log_path"))
                .and_then(|p| p.as_str())
                .unwrap_or("/var/log/execwall/agent-audit.jsonl")
        )?;

        Ok(Self {
            policy_path: policy_path.as_ref().to_string_lossy().to_string(),
            tools,
            profiles,
            audit_logger,
        })
    }

    /// Execute a tool call with policy enforcement
    pub fn execute(&self, call: ToolCall) -> Result<ToolResult, String> {
        let start = std::time::Instant::now();

        // Check if tool is defined
        let tool_def = match self.tools.get(&call.tool) {
            Some(def) => def,
            None => {
                self.audit_logger.log_denial(&call.tool, &call.identity, "Tool not defined");
                return Ok(ToolResult {
                    allowed: false,
                    success: false,
                    data: serde_json::json!({}),
                    error: Some(format!("Tool '{}' not defined in policy", call.tool)),
                    requires_approval: false,
                    execution_ms: start.elapsed().as_millis() as u64,
                    profile_used: None,
                });
            }
        };

        // Get profile
        let profile = self.profiles.get(&tool_def.profile);
        let requires_approval = profile.map(|p| p.require_approval).unwrap_or(false);

        // Check approval token for write tools
        if requires_approval && call.approval_token.is_none() {
            self.audit_logger.log_denial(&call.tool, &call.identity, "Requires approval");
            return Ok(ToolResult {
                allowed: false,
                success: false,
                data: serde_json::json!({}),
                error: Some("This tool requires an approval token".to_string()),
                requires_approval: true,
                execution_ms: start.elapsed().as_millis() as u64,
                profile_used: Some(tool_def.profile.clone()),
            });
        }

        // Execute the tool
        let json_args = serde_json::to_string(&call.args)
            .map_err(|e| format!("Failed to serialize args: {}", e))?;

        let mut cmd = Command::new("python3");
        cmd.arg(&tool_def.path)
            .arg("--json")
            .arg(&json_args);

        // Inject environment variables from profile
        if let Some(profile) = profile {
            for (key, value) in &profile.env_inject {
                cmd.env(key, value);
            }
        }

        let output = cmd.output()
            .map_err(|e| format!("Failed to execute tool: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result_data: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| serde_json::json!({
                "success": false,
                "error": "Failed to parse tool output"
            }));

        let success = result_data.get("success")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        self.audit_logger.log_execution(
            &call.tool,
            &call.identity,
            &tool_def.profile,
            success,
            start.elapsed().as_millis() as u64,
        );

        Ok(ToolResult {
            allowed: true,
            success,
            data: result_data.get("data").cloned().unwrap_or(serde_json::json!({})),
            error: result_data.get("error").and_then(|e| e.as_str()).map(String::from),
            requires_approval: false,
            execution_ms: start.elapsed().as_millis() as u64,
            profile_used: Some(tool_def.profile.clone()),
        })
    }

    /// Get list of available tools
    pub fn list_tools(&self) -> Vec<(String, String)> {
        self.tools.iter()
            .map(|(name, def)| {
                (name.clone(), def.description.clone().unwrap_or_default())
            })
            .collect()
    }
}
```

**Step 4: Update lib.rs**

```rust
// Add to src/lib.rs
pub mod agent_runner;
```

**Step 5: Run test to verify it passes**

Run: `cargo test agent_runner`
Expected: PASS (3 tests)

**Step 6: Commit**

```bash
git add src/agent_runner.rs src/lib.rs tests/agent_runner_test.rs
git commit -m "feat: add AgentRunner for Claude SDK tool execution"
```

---

## Phase 3: Claude Agent SDK Integration

### Task 7: Create Python Agent SDK Wrapper

**Files:**
- Create: `agent/execwall_agent.py`
- Create: `agent/tool_definitions.py`
- Test: `agent/tests/test_agent.py`

**Step 1: Write the failing test**

```python
# agent/tests/test_agent.py
import pytest
from unittest.mock import patch, MagicMock
from execwall_agent import ExecwallAgent

def test_agent_registers_tools():
    """Agent should register all tools from policy."""
    agent = ExecwallAgent(policy_path="policy-agent.yaml")
    tools = agent.get_available_tools()

    assert "cal_read" in tools
    assert "web_search" in tools
    assert "cal_create" in tools

def test_agent_executes_tool_through_execwall():
    """Agent should execute tools through execwall_run."""
    agent = ExecwallAgent(policy_path="policy-agent.yaml")

    with patch.object(agent, '_execwall_run') as mock_run:
        mock_run.return_value = {
            "allowed": True,
            "success": True,
            "data": {"events": []}
        }

        result = agent.execute_tool("cal_read", {"date": "2026-02-28"})

    mock_run.assert_called_once()
    assert result["success"] is True

def test_agent_blocks_direct_shell():
    """Agent should not allow direct shell execution."""
    agent = ExecwallAgent(policy_path="policy-agent.yaml")

    with pytest.raises(ValueError, match="shell"):
        agent.execute_tool("bash", {"command": "ls"})
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest agent/tests/test_agent.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# agent/execwall_agent.py
"""Claude Agent SDK wrapper with Execwall enforcement."""
import json
import subprocess
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

@dataclass
class ToolDefinition:
    """Tool definition for Claude SDK."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    profile: str
    requires_approval: bool = False

class ExecwallAgent:
    """Agent that executes all tools through Execwall."""

    BLOCKED_TOOLS = {"bash", "shell", "exec", "system", "eval", "subprocess"}

    def __init__(
        self,
        policy_path: str = "/etc/execwall/policy-agent.yaml",
        execwall_socket: str = "localhost:9999"
    ):
        self.policy_path = policy_path
        self.execwall_socket = execwall_socket
        self._tools = self._load_tools()

    def _load_tools(self) -> Dict[str, ToolDefinition]:
        """Load tool definitions from policy."""
        import yaml

        with open(self.policy_path, "r") as f:
            policy = yaml.safe_load(f)

        tools = {}
        for name, config in policy.get("tools", {}).items():
            profile = config.get("profile", "tools_readonly")
            profile_config = policy.get("profiles", {}).get(profile, {})

            tools[name] = ToolDefinition(
                name=name,
                description=config.get("description", ""),
                input_schema=self._get_tool_schema(config.get("path", "")),
                profile=profile,
                requires_approval=profile_config.get("require_approval", False)
            )

        return tools

    def _get_tool_schema(self, tool_path: str) -> Dict[str, Any]:
        """Extract input schema from tool (introspection)."""
        # In production, tools would export their schema
        return {
            "type": "object",
            "properties": {},
            "required": []
        }

    def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        return list(self._tools.keys())

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Get Claude SDK tool definitions."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema
            }
            for tool in self._tools.values()
        ]

    def _execwall_run(
        self,
        tool: str,
        args: Dict[str, Any],
        identity: str = "claude-agent",
        approval_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute tool through Execwall."""
        request = {
            "tool": tool,
            "args": args,
            "identity": identity
        }
        if approval_token:
            request["approval_token"] = approval_token

        # Use execwall binary with JSON API
        result = subprocess.run(
            ["/usr/local/bin/execwall", "--api-call", json.dumps(request)],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return {
                "allowed": False,
                "success": False,
                "error": f"Execwall error: {result.stderr}"
            }

        return json.loads(result.stdout)

    def execute_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        approval_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute a tool with Execwall enforcement."""
        # Block dangerous tools
        if tool_name.lower() in self.BLOCKED_TOOLS:
            raise ValueError(f"Direct shell/exec tools are blocked: {tool_name}")

        # Check tool exists
        if tool_name not in self._tools:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not available"
            }

        # Check if approval required
        tool = self._tools[tool_name]
        if tool.requires_approval and not approval_token:
            return {
                "success": False,
                "requires_approval": True,
                "error": f"Tool '{tool_name}' requires approval token"
            }

        # Execute through Execwall
        return self._execwall_run(tool_name, args, approval_token=approval_token)

    def request_approval(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Request approval for write operation (returns request ID)."""
        # In production, this would create a pending approval request
        import uuid
        request_id = str(uuid.uuid4())

        # Store pending request for user approval
        # ... approval workflow implementation ...

        return request_id
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/sundarsubramaniam/sentra-install && python -m pytest agent/tests/test_agent.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add agent/
git commit -m "feat: add ExecwallAgent wrapper for Claude SDK"
```

---

### Task 8: Create Claude Agent Entry Point

**Files:**
- Create: `agent/main.py`
- Create: `agent/config.yaml`

**Step 1: Write the implementation**

```python
#!/usr/bin/env python3
# agent/main.py
"""Claude Agent with Execwall security enforcement."""
import os
import json
import asyncio
from typing import Any, Dict
from anthropic import Anthropic
from execwall_agent import ExecwallAgent

class SecureClaudeAgent:
    """Claude agent that executes all tools through Execwall."""

    def __init__(self, config_path: str = "config.yaml"):
        import yaml
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.client = Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )

        self.execwall = ExecwallAgent(
            policy_path=self.config.get("policy_path", "/etc/execwall/policy-agent.yaml")
        )

        self.model = self.config.get("model", "claude-sonnet-4-20250514")
        self.max_tokens = self.config.get("max_tokens", 4096)
        self.conversation_history = []

    def _get_tools(self):
        """Get tool definitions for Claude API."""
        tools = []
        for tool_def in self.execwall.get_tool_definitions():
            tools.append({
                "name": tool_def["name"],
                "description": tool_def["description"],
                "input_schema": tool_def["input_schema"]
            })
        return tools

    def _handle_tool_use(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """Handle tool use through Execwall."""
        result = self.execwall.execute_tool(tool_name, tool_input)
        return json.dumps(result)

    async def chat(self, user_message: str) -> str:
        """Process user message with tool execution."""
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        # Initial response
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            tools=self._get_tools(),
            messages=self.conversation_history
        )

        # Handle tool use loop
        while response.stop_reason == "tool_use":
            # Extract tool use
            tool_use_block = next(
                block for block in response.content
                if block.type == "tool_use"
            )

            # Execute through Execwall
            tool_result = self._handle_tool_use(
                tool_use_block.name,
                tool_use_block.input
            )

            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": response.content
            })
            self.conversation_history.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_block.id,
                    "content": tool_result
                }]
            })

            # Continue conversation
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                tools=self._get_tools(),
                messages=self.conversation_history
            )

        # Extract final text
        final_text = "".join(
            block.text for block in response.content
            if hasattr(block, "text")
        )

        self.conversation_history.append({
            "role": "assistant",
            "content": final_text
        })

        return final_text

async def main():
    """Main entry point."""
    agent = SecureClaudeAgent()

    print("Secure Claude Agent (Execwall-enforced)")
    print("Type 'quit' to exit\n")

    while True:
        try:
            user_input = input("You: ").strip()
            if user_input.lower() in ("quit", "exit"):
                break

            response = await agent.chat(user_input)
            print(f"\nAgent: {response}\n")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

```yaml
# agent/config.yaml
# Claude Agent Configuration

# Model settings
model: "claude-sonnet-4-20250514"
max_tokens: 4096
temperature: 0.7

# Execwall policy
policy_path: "/etc/execwall/policy-agent.yaml"

# Agent identity (for audit)
identity: "claude-agent-prod"

# Rate limits (agent-level)
rate_limits:
  requests_per_minute: 60
  tool_calls_per_minute: 30

# Approval settings
approval:
  auto_approve_readonly: true
  timeout_seconds: 300
```

**Step 2: Commit**

```bash
git add agent/main.py agent/config.yaml
git commit -m "feat: add Claude Agent entry point with Execwall integration"
```

---

## Phase 4: Security Hardening

### Task 9: Create Planner Lockdown Profile

**Files:**
- Create: `profiles/planner-lockdown.yaml`
- Create: `scripts/setup-planner-container.sh`

**Step 1: Create lockdown profile**

```yaml
# profiles/planner-lockdown.yaml
# Seccomp + namespace profile for planner process
# Only allows execwall_client execution

version: "1.0"
description: "Lockdown profile for Claude Agent planner process"

# Only these binaries can be executed
allowed_executables:
  - /usr/local/bin/execwall
  - /usr/bin/python3
  - /usr/lib/execwall/agent/main.py

# Block all others
blocked_patterns:
  - /bin/bash
  - /bin/sh
  - /usr/bin/bash
  - /usr/bin/sh
  - /bin/dash
  - /usr/bin/env

# Network restrictions
network:
  # Only allow Anthropic API
  allow_outbound:
    - "api.anthropic.com:443"
    - "localhost:9999"  # Execwall socket
  block_metadata:
    - "169.254.169.254"  # AWS metadata
    - "metadata.google.internal"

# Filesystem
filesystem:
  read_only:
    - /usr/lib/execwall
    - /etc/execwall
  read_write:
    - /work
    - /tmp/agent
  blocked:
    - /etc/passwd
    - /etc/shadow
    - /root
    - /home

# Resource limits
limits:
  memory_mb: 1024
  cpu_percent: 50
  open_files: 256
  processes: 32

# Seccomp syscall filter
seccomp:
  default: deny
  allow:
    # Basic operations
    - read
    - write
    - open
    - openat
    - close
    - stat
    - fstat
    - lstat
    - poll
    - lseek
    - mmap
    - mprotect
    - munmap
    - brk
    # Networking (restricted)
    - socket
    - connect
    - sendto
    - recvfrom
    - sendmsg
    - recvmsg
    # Process (restricted)
    - clone  # For threads only, not fork
    - execve  # Only allowed binaries
    - wait4
    - exit
    - exit_group
    # Time
    - gettimeofday
    - clock_gettime
    - nanosleep
    # Other
    - futex
    - set_tid_address
    - set_robust_list
    - getrandom

  # These are always blocked
  deny_always:
    - ptrace
    - mount
    - umount2
    - pivot_root
    - chroot
    - setuid
    - setgid
    - setreuid
    - setregid
    - setresuid
    - setresgid
    - fork  # Block fork, only allow clone for threads
    - vfork
    - init_module
    - delete_module
    - kexec_load
    - reboot
    - sethostname
    - setdomainname
```

**Step 2: Create container setup script**

```bash
#!/bin/bash
# scripts/setup-planner-container.sh
# Sets up the planner container with minimal attack surface

set -euo pipefail

CONTAINER_NAME="execwall-planner"
IMAGE_NAME="execwall-planner:latest"

# Build minimal container image
cat > /tmp/Dockerfile.planner << 'EOF'
FROM python:3.11-slim

# Remove shells
RUN rm -f /bin/bash /bin/sh /usr/bin/bash /usr/bin/sh && \
    ln -s /usr/local/bin/execwall /bin/sh

# Install only required packages
RUN pip install --no-cache-dir anthropic pyyaml

# Copy agent code
COPY agent/ /usr/lib/execwall/agent/
COPY profiles/planner-lockdown.yaml /etc/execwall/

# Create non-root user
RUN useradd -r -s /sbin/nologin agent && \
    mkdir -p /work /tmp/agent && \
    chown -R agent:agent /work /tmp/agent

USER agent
WORKDIR /work

# Only entry point is the agent
ENTRYPOINT ["python3", "/usr/lib/execwall/agent/main.py"]
EOF

# Build image
docker build -t "$IMAGE_NAME" -f /tmp/Dockerfile.planner .

echo "Planner container image built: $IMAGE_NAME"
echo ""
echo "Run with:"
echo "  docker run --rm -it \\"
echo "    --security-opt seccomp=/etc/execwall/planner-seccomp.json \\"
echo "    --cap-drop ALL \\"
echo "    --read-only \\"
echo "    --tmpfs /tmp:rw,noexec,nosuid \\"
echo "    -e ANTHROPIC_API_KEY \\"
echo "    -v /var/run/execwall:/var/run/execwall:ro \\"
echo "    $IMAGE_NAME"
```

**Step 3: Commit**

```bash
git add profiles/ scripts/
git commit -m "feat: add planner lockdown profile and container setup"
```

---

### Task 10: Create Secrets Injection System

**Files:**
- Create: `src/secrets.rs`
- Modify: `src/agent_runner.rs`

**Step 1: Write the implementation**

```rust
// src/secrets.rs
//! Secure secrets injection - tools never see raw secrets.

use std::collections::HashMap;
use std::env;
use std::process::Command;

/// Secret source types
#[derive(Debug, Clone)]
pub enum SecretSource {
    /// Environment variable
    Env(String),
    /// OS keychain (macOS Keychain, Linux Secret Service)
    Keychain { service: String, account: String },
    /// External secret manager (HashiCorp Vault, AWS Secrets Manager)
    External { provider: String, path: String },
}

/// Secrets manager for tool execution
pub struct SecretsManager {
    /// Tool-specific secret mappings
    tool_secrets: HashMap<String, Vec<(String, SecretSource)>>,
}

impl SecretsManager {
    pub fn new() -> Self {
        Self {
            tool_secrets: HashMap::new(),
        }
    }

    /// Load tool secret mappings from policy
    pub fn load_from_policy(&mut self, policy_path: &str) -> Result<(), String> {
        let policy_str = std::fs::read_to_string(policy_path)
            .map_err(|e| format!("Failed to read policy: {}", e))?;

        let policy: serde_yaml::Value = serde_yaml::from_str(&policy_str)
            .map_err(|e| format!("Failed to parse policy: {}", e))?;

        // Extract secrets configuration
        if let Some(secrets) = policy.get("secrets") {
            if let Some(tools) = secrets.get("tools") {
                for (tool_name, config) in tools.as_mapping().unwrap_or(&serde_yaml::Mapping::new()) {
                    let name = tool_name.as_str().unwrap_or("").to_string();
                    let mut mappings = Vec::new();

                    if let Some(env_map) = config.get("env") {
                        for (env_var, source) in env_map.as_mapping().unwrap_or(&serde_yaml::Mapping::new()) {
                            let var_name = env_var.as_str().unwrap_or("").to_string();

                            if let Some(from_env) = source.get("from_env") {
                                mappings.push((
                                    var_name,
                                    SecretSource::Env(from_env.as_str().unwrap_or("").to_string())
                                ));
                            } else if let Some(from_keychain) = source.get("from_keychain") {
                                mappings.push((
                                    var_name,
                                    SecretSource::Keychain {
                                        service: from_keychain.get("service")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                        account: from_keychain.get("account")
                                            .and_then(|a| a.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                    }
                                ));
                            }
                        }
                    }

                    self.tool_secrets.insert(name, mappings);
                }
            }
        }

        Ok(())
    }

    /// Get environment variables to inject for a specific tool
    pub fn get_env_for_tool(&self, tool_name: &str) -> HashMap<String, String> {
        let mut env_vars = HashMap::new();

        if let Some(mappings) = self.tool_secrets.get(tool_name) {
            for (var_name, source) in mappings {
                if let Some(value) = self.resolve_secret(source) {
                    env_vars.insert(var_name.clone(), value);
                }
            }
        }

        env_vars
    }

    fn resolve_secret(&self, source: &SecretSource) -> Option<String> {
        match source {
            SecretSource::Env(var_name) => {
                env::var(var_name).ok()
            }
            SecretSource::Keychain { service, account } => {
                self.get_keychain_secret(service, account)
            }
            SecretSource::External { provider, path } => {
                self.get_external_secret(provider, path)
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn get_keychain_secret(&self, service: &str, account: &str) -> Option<String> {
        let output = Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .ok()?;

        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn get_keychain_secret(&self, service: &str, account: &str) -> Option<String> {
        // Linux: use secret-tool from libsecret
        let output = Command::new("secret-tool")
            .args(["lookup", "service", service, "account", account])
            .output()
            .ok()?;

        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    fn get_external_secret(&self, _provider: &str, _path: &str) -> Option<String> {
        // TODO: Implement Vault, AWS Secrets Manager, etc.
        None
    }
}
```

**Step 2: Add secrets configuration to policy**

```yaml
# Add to policy-agent.yaml
secrets:
  # Global settings
  redact_in_logs: true
  rotation_check_hours: 24

  # Per-tool secret injection
  tools:
    cal_read:
      env:
        GOOGLE_APPLICATION_CREDENTIALS:
          from_keychain:
            service: "execwall"
            account: "google-calendar-readonly"

    cal_create:
      env:
        GOOGLE_APPLICATION_CREDENTIALS:
          from_keychain:
            service: "execwall"
            account: "google-calendar-write"

    slack_post:
      env:
        SLACK_BOT_TOKEN:
          from_keychain:
            service: "execwall"
            account: "slack-bot"

    email_send:
      env:
        GMAIL_APP_PASSWORD:
          from_keychain:
            service: "execwall"
            account: "gmail-app-password"
```

**Step 3: Commit**

```bash
git add src/secrets.rs policy-agent.yaml
git commit -m "feat: add secure secrets injection system"
```

---

## Phase 5: Observability

### Task 11: Create Structured Audit System

**Files:**
- Modify: `src/audit.rs` (extend existing)
- Create: `tools/audit_viewer.py`

**Step 1: Extend audit module**

```rust
// Add to src/audit.rs

/// Agent-specific audit events
#[derive(Debug, Serialize)]
pub struct AgentAuditEvent {
    pub timestamp: String,
    pub event_type: AgentEventType,
    pub agent_id: String,
    pub tool_name: Option<String>,
    pub profile: Option<String>,
    pub decision: AuditDecision,
    pub execution_ms: Option<u64>,
    pub input_bytes: Option<usize>,
    pub output_bytes: Option<usize>,
    pub rule_matched: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEventType {
    ToolCall,
    ToolResult,
    ApprovalRequest,
    ApprovalGranted,
    ApprovalDenied,
    RateLimitExceeded,
    PolicyDenial,
    SecretAccess,
    SessionStart,
    SessionEnd,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Denied,
    RequiresApproval,
    AuditOnly,
}

impl AuditLogger {
    /// Log agent tool call
    pub fn log_tool_call(
        &self,
        agent_id: &str,
        tool_name: &str,
        profile: &str,
        input_bytes: usize,
    ) {
        let event = AgentAuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: AgentEventType::ToolCall,
            agent_id: agent_id.to_string(),
            tool_name: Some(tool_name.to_string()),
            profile: Some(profile.to_string()),
            decision: AuditDecision::Allowed,
            execution_ms: None,
            input_bytes: Some(input_bytes),
            output_bytes: None,
            rule_matched: None,
            error: None,
        };

        self.write_event(&event);
    }

    /// Log tool execution result
    pub fn log_tool_result(
        &self,
        agent_id: &str,
        tool_name: &str,
        success: bool,
        execution_ms: u64,
        output_bytes: usize,
    ) {
        let event = AgentAuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: AgentEventType::ToolResult,
            agent_id: agent_id.to_string(),
            tool_name: Some(tool_name.to_string()),
            profile: None,
            decision: if success { AuditDecision::Allowed } else { AuditDecision::Denied },
            execution_ms: Some(execution_ms),
            input_bytes: None,
            output_bytes: Some(output_bytes),
            rule_matched: None,
            error: None,
        };

        self.write_event(&event);
    }

    /// Log policy denial
    pub fn log_denial(
        &self,
        tool_name: &str,
        agent_id: &str,
        reason: &str,
    ) {
        let event = AgentAuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: AgentEventType::PolicyDenial,
            agent_id: agent_id.to_string(),
            tool_name: Some(tool_name.to_string()),
            profile: None,
            decision: AuditDecision::Denied,
            execution_ms: None,
            input_bytes: None,
            output_bytes: None,
            rule_matched: None,
            error: Some(reason.to_string()),
        };

        self.write_event(&event);
    }

    fn write_event<T: Serialize>(&self, event: &T) {
        if let Ok(json) = serde_json::to_string(event) {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
            {
                use std::io::Write;
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}
```

**Step 2: Create audit viewer**

```python
#!/usr/bin/env python3
# tools/audit_viewer.py
"""Audit log viewer and analyzer."""
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

def load_audit_log(path: str) -> List[Dict]:
    """Load JSON Lines audit log."""
    events = []
    with open(path, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return events

def analyze_events(events: List[Dict]) -> Dict:
    """Analyze audit events for anomalies."""
    analysis = {
        "total_events": len(events),
        "by_type": defaultdict(int),
        "by_tool": defaultdict(int),
        "denials": [],
        "high_frequency": [],
        "large_outputs": [],
    }

    # Time window tracking
    time_windows = defaultdict(list)

    for event in events:
        event_type = event.get("event_type", "unknown")
        analysis["by_type"][event_type] += 1

        if tool := event.get("tool_name"):
            analysis["by_tool"][tool] += 1

        # Track denials
        if event.get("decision") == "denied":
            analysis["denials"].append({
                "timestamp": event.get("timestamp"),
                "tool": event.get("tool_name"),
                "reason": event.get("error"),
            })

        # Track large outputs (potential exfil)
        if (output_bytes := event.get("output_bytes", 0)) > 1_000_000:
            analysis["large_outputs"].append({
                "timestamp": event.get("timestamp"),
                "tool": event.get("tool_name"),
                "bytes": output_bytes,
            })

        # Track frequency by minute
        if ts := event.get("timestamp"):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                minute_key = dt.strftime("%Y-%m-%d %H:%M")
                time_windows[minute_key].append(event)
            except ValueError:
                pass

    # Detect high frequency windows
    for minute, window_events in time_windows.items():
        if len(window_events) > 30:  # Threshold
            analysis["high_frequency"].append({
                "window": minute,
                "count": len(window_events),
            })

    return analysis

def print_report(analysis: Dict):
    """Print analysis report."""
    print("=" * 60)
    print("EXECWALL AUDIT REPORT")
    print("=" * 60)
    print(f"\nTotal Events: {analysis['total_events']}")

    print("\nEvents by Type:")
    for event_type, count in sorted(analysis["by_type"].items()):
        print(f"  {event_type}: {count}")

    print("\nEvents by Tool:")
    for tool, count in sorted(analysis["by_tool"].items(), key=lambda x: -x[1])[:10]:
        print(f"  {tool}: {count}")

    if analysis["denials"]:
        print(f"\n⚠️  DENIALS ({len(analysis['denials'])}):")
        for d in analysis["denials"][:5]:
            print(f"  [{d['timestamp']}] {d['tool']}: {d['reason']}")

    if analysis["large_outputs"]:
        print(f"\n⚠️  LARGE OUTPUTS ({len(analysis['large_outputs'])}):")
        for lo in analysis["large_outputs"]:
            print(f"  [{lo['timestamp']}] {lo['tool']}: {lo['bytes']:,} bytes")

    if analysis["high_frequency"]:
        print(f"\n⚠️  HIGH FREQUENCY WINDOWS:")
        for hf in analysis["high_frequency"]:
            print(f"  {hf['window']}: {hf['count']} events")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/execwall/agent-audit.jsonl"
    events = load_audit_log(log_path)
    analysis = analyze_events(events)
    print_report(analysis)
```

**Step 3: Commit**

```bash
git add src/audit.rs tools/audit_viewer.py
git commit -m "feat: add comprehensive agent audit logging and viewer"
```

---

## Summary: Tool and Profile Mapping

| Tool | Profile | Privilege | Approval Required |
|------|---------|-----------|-------------------|
| cal_read | tools_readonly | Low | No |
| news_search / web_search | tools_readonly | Low | No |
| ib_status | tools_readonly | Low | No |
| crypto_price | tools_readonly | Low | No |
| stock_price | tools_readonly | Low | No |
| cal_create | tools_write | High | Yes |
| slack_post | tools_write | High | Yes |
| wa_send | tools_write | High | Yes |
| email_send | tools_write | High | Yes |
| github_issue_create | tools_write | High | Yes |
| browser_download | browser_automation | Very High | Yes |

## Implementation Order

1. **Phase 1**: CLI Tool Framework (Tasks 1-4)
2. **Phase 2**: Execwall Policy Profiles (Tasks 5-6)
3. **Phase 3**: Claude Agent SDK Integration (Tasks 7-8)
4. **Phase 4**: Security Hardening (Tasks 9-10)
5. **Phase 5**: Observability (Task 11)

## Critical Security Invariants

1. **No raw shell access** - All execution through named tools
2. **JSON schema validation** - All inputs validated before execution
3. **Deny-by-default** - Only explicitly allowed tools work
4. **Approval tokens for writes** - Exfil vectors require human approval
5. **Secrets never readable by agent** - Injected per-tool by Execwall
6. **Full audit trail** - Every action logged with identity

---

## Phase 6: Memory & Persistence (SQLite)

**Decision: SQLite over Obsidian**
- Structured data (tasks, events, memory) needs queries, not markdown
- Already installed on Oracle instance (`sqlite3` CLI)
- Execwall can wrap `sqlite3` with JSON output
- No sync conflicts, single-file database

### Task 12: Create Memory Database Schema

**Files:**
- Create: `tools/memory_db.py`
- Create: `schema/agent_memory.sql`
- Test: `tools/tests/test_memory_db.py`

**Step 1: Write the failing test**

```python
# tools/tests/test_memory_db.py
import pytest
import tempfile
import os
from memory_db import MemoryDB

def test_memory_db_creates_tables():
    """Database should create required tables on init."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        db = MemoryDB(db_path)
        tables = db.list_tables()

        assert "tasks" in tables
        assert "notes" in tables
        assert "events" in tables
        assert "reminders" in tables
    finally:
        os.unlink(db_path)

def test_memory_db_adds_task():
    """Should add and retrieve tasks."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        db = MemoryDB(db_path)
        task_id = db.add_task("Buy groceries", priority=2, due="2026-02-28")

        tasks = db.get_pending_tasks()
        assert len(tasks) == 1
        assert tasks[0]["content"] == "Buy groceries"
        assert tasks[0]["priority"] == 2
    finally:
        os.unlink(db_path)

def test_memory_db_stores_notes_with_tags():
    """Should store notes with searchable tags."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        db = MemoryDB(db_path)
        db.remember("Meeting notes: discussed Q1 targets", tags=["meeting", "q1"])

        results = db.recall("Q1")
        assert len(results) >= 1
        assert "Q1" in results[0]["content"]

        results = db.recall_by_tag("meeting")
        assert len(results) >= 1
    finally:
        os.unlink(db_path)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tools/tests/test_memory_db.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write schema**

```sql
-- schema/agent_memory.sql
-- Agent memory and task database

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    priority INTEGER DEFAULT 3,  -- 1=urgent, 2=high, 3=normal, 4=low
    status TEXT DEFAULT 'pending',  -- pending, in_progress, completed, cancelled
    due_at TEXT,  -- ISO 8601 datetime
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    source TEXT,  -- 'user', 'email', 'whatsapp', 'calendar', 'system'
    source_id TEXT,  -- reference to original message/event
    tags TEXT  -- JSON array
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    tags TEXT,  -- JSON array
    created_at TEXT DEFAULT (datetime('now')),
    source TEXT,
    embedding BLOB  -- for future semantic search
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,  -- 'email_received', 'whatsapp_received', 'calendar_reminder', etc.
    payload TEXT NOT NULL,  -- JSON
    processed BOOLEAN DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    processed_at TEXT
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER REFERENCES tasks(id),
    remind_at TEXT NOT NULL,  -- ISO 8601 datetime
    channel TEXT DEFAULT 'whatsapp',  -- 'whatsapp', 'email', 'slack'
    sent BOOLEAN DEFAULT 0,
    sent_at TEXT
);

CREATE TABLE IF NOT EXISTS conversation_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,  -- 'user', 'assistant'
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, created_at);
CREATE INDEX IF NOT EXISTS idx_reminders_pending ON reminders(sent, remind_at);
CREATE INDEX IF NOT EXISTS idx_notes_tags ON notes(tags);

-- Full-text search for notes
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(content, tags, content='notes', content_rowid='id');

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO notes_fts(rowid, content, tags) VALUES (new.id, new.content, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, content, tags) VALUES ('delete', old.id, old.content, old.tags);
END;
```

**Step 4: Write implementation**

```python
#!/usr/bin/env python3
# tools/memory_db.py
"""SQLite-based memory and task management for the agent."""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class MemoryDB:
    """Agent memory database."""

    def __init__(self, db_path: str = "/var/lib/execwall/agent_memory.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database with schema."""
        schema_path = Path(__file__).parent.parent / "schema" / "agent_memory.sql"
        with open(schema_path, "r") as f:
            schema = f.read()

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(schema)

    def _dict_factory(self, cursor, row):
        """Convert rows to dicts."""
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

    def list_tables(self) -> List[str]:
        """List all tables in database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            return [row[0] for row in cursor.fetchall()]

    # Task management
    def add_task(
        self,
        content: str,
        priority: int = 3,
        due: Optional[str] = None,
        source: str = "user",
        source_id: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> int:
        """Add a new task."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO tasks (content, priority, due_at, source, source_id, tags)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (content, priority, due, source, source_id, json.dumps(tags or []))
            )
            return cursor.lastrowid

    def get_pending_tasks(self, limit: int = 50) -> List[Dict]:
        """Get pending tasks ordered by priority and due date."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._dict_factory
            cursor = conn.execute(
                """SELECT * FROM tasks
                   WHERE status = 'pending'
                   ORDER BY priority ASC, due_at ASC NULLS LAST
                   LIMIT ?""",
                (limit,)
            )
            return cursor.fetchall()

    def complete_task(self, task_id: int) -> bool:
        """Mark task as completed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE tasks SET status = 'completed', completed_at = datetime('now')
                   WHERE id = ?""",
                (task_id,)
            )
            return cursor.rowcount > 0

    # Notes/Memory
    def remember(self, content: str, tags: Optional[List[str]] = None, source: str = "user") -> int:
        """Store a note in memory."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO notes (content, tags, source)
                   VALUES (?, ?, ?)""",
                (content, json.dumps(tags or []), source)
            )
            return cursor.lastrowid

    def recall(self, query: str, limit: int = 10) -> List[Dict]:
        """Search notes using full-text search."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._dict_factory
            cursor = conn.execute(
                """SELECT notes.* FROM notes_fts
                   JOIN notes ON notes_fts.rowid = notes.id
                   WHERE notes_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (query, limit)
            )
            return cursor.fetchall()

    def recall_by_tag(self, tag: str) -> List[Dict]:
        """Get notes by tag."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._dict_factory
            cursor = conn.execute(
                """SELECT * FROM notes WHERE tags LIKE ?
                   ORDER BY created_at DESC""",
                (f'%"{tag}"%',)
            )
            return cursor.fetchall()

    # Events (for input monitoring)
    def log_event(self, event_type: str, payload: Dict) -> int:
        """Log an incoming event for processing."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO events (event_type, payload)
                   VALUES (?, ?)""",
                (event_type, json.dumps(payload))
            )
            return cursor.lastrowid

    def get_unprocessed_events(self, limit: int = 100) -> List[Dict]:
        """Get events that haven't been processed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._dict_factory
            cursor = conn.execute(
                """SELECT * FROM events
                   WHERE processed = 0
                   ORDER BY created_at ASC
                   LIMIT ?""",
                (limit,)
            )
            return cursor.fetchall()

    def mark_event_processed(self, event_id: int):
        """Mark event as processed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE events SET processed = 1, processed_at = datetime('now')
                   WHERE id = ?""",
                (event_id,)
            )

    # Reminders
    def add_reminder(self, task_id: int, remind_at: str, channel: str = "whatsapp") -> int:
        """Schedule a reminder for a task."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO reminders (task_id, remind_at, channel)
                   VALUES (?, ?, ?)""",
                (task_id, remind_at, channel)
            )
            return cursor.lastrowid

    def get_due_reminders(self) -> List[Dict]:
        """Get reminders that are due now."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._dict_factory
            cursor = conn.execute(
                """SELECT r.*, t.content as task_content
                   FROM reminders r
                   JOIN tasks t ON r.task_id = t.id
                   WHERE r.sent = 0 AND r.remind_at <= datetime('now')
                   ORDER BY r.remind_at ASC"""
            )
            return cursor.fetchall()

    def mark_reminder_sent(self, reminder_id: int):
        """Mark reminder as sent."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE reminders SET sent = 1, sent_at = datetime('now')
                   WHERE id = ?""",
                (reminder_id,)
            )


# CLI Tools wrapping MemoryDB
class TaskAddTool(ToolBase):
    """Add a task to the task list."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "content": {"type": "string", "minLength": 1},
            "priority": {"type": "integer", "minimum": 1, "maximum": 4, "default": 3},
            "due": {"type": "string", "format": "date-time"},
            "tags": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["content"]
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        db = MemoryDB()
        task_id = db.add_task(
            content=request.params["content"],
            priority=request.params.get("priority", 3),
            due=request.params.get("due"),
            tags=request.params.get("tags")
        )
        return ToolResponse(success=True, data={"task_id": task_id})


class TaskListTool(ToolBase):
    """List pending tasks."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "default": 20}
        }
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        db = MemoryDB()
        tasks = db.get_pending_tasks(limit=request.params.get("limit", 20))
        return ToolResponse(success=True, data={"tasks": tasks, "count": len(tasks)})


class RememberTool(ToolBase):
    """Store information in memory."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "content": {"type": "string", "minLength": 1},
            "tags": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["content"]
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        db = MemoryDB()
        note_id = db.remember(
            content=request.params["content"],
            tags=request.params.get("tags")
        )
        return ToolResponse(success=True, data={"note_id": note_id})


class RecallTool(ToolBase):
    """Search memory for information."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1},
            "limit": {"type": "integer", "default": 10}
        },
        "required": ["query"]
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        db = MemoryDB()
        results = db.recall(
            query=request.params["query"],
            limit=request.params.get("limit", 10)
        )
        return ToolResponse(success=True, data={"results": results, "count": len(results)})
```

**Step 5: Run tests**

Run: `python -m pytest tools/tests/test_memory_db.py -v`
Expected: PASS (3 tests)

**Step 6: Commit**

```bash
git add tools/memory_db.py schema/agent_memory.sql tools/tests/test_memory_db.py
git commit -m "feat: add SQLite memory database for tasks and notes"
```

---

## Phase 7: Event Monitoring (WhatsApp + Email)

### Task 13: Create Event Monitor Daemon

**Files:**
- Create: `agent/event_monitor.py`
- Create: `tools/email_poll.py`
- Create: `tools/whatsapp_poll.py`

**Step 1: Write the event monitor**

```python
#!/usr/bin/env python3
# agent/event_monitor.py
"""
Event monitor daemon - polls WhatsApp and Email for new messages.
Logs events to SQLite for agent processing.
"""
import json
import os
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools.memory_db import MemoryDB

class EventMonitor:
    """Monitors external channels for incoming events."""

    def __init__(
        self,
        poll_interval: int = 30,  # seconds
        db_path: str = "/var/lib/execwall/agent_memory.db"
    ):
        self.poll_interval = poll_interval
        self.db = MemoryDB(db_path)
        self.last_email_check = None
        self.last_whatsapp_check = None

    def poll_email(self) -> List[Dict]:
        """Poll for new emails using himalaya CLI."""
        try:
            result = subprocess.run(
                [os.path.expanduser("~/.local/bin/himalaya"), "envelope", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return []

            envelopes = json.loads(result.stdout)

            # Filter for new/unread emails
            new_emails = []
            for env in envelopes:
                if not env.get("flags", {}).get("seen", False):
                    # Fetch full email
                    read_result = subprocess.run(
                        [os.path.expanduser("~/.local/bin/himalaya"), "message", "read", str(env["id"]), "--format", "json"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if read_result.returncode == 0:
                        email_data = json.loads(read_result.stdout)
                        new_emails.append({
                            "id": env["id"],
                            "from": env.get("from", {}).get("addr", "unknown"),
                            "subject": env.get("subject", ""),
                            "date": env.get("date", ""),
                            "body": email_data.get("body", {}).get("text", "")[:2000]  # Truncate
                        })

            return new_emails

        except Exception as e:
            print(f"Email poll error: {e}")
            return []

    def poll_whatsapp(self) -> List[Dict]:
        """Poll for new WhatsApp messages."""
        try:
            # WhatsApp CLI tool (using existing integration)
            result = subprocess.run(
                [os.path.expanduser("~/.local/bin/wa_poll"), "--json", "--unread"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return []

            messages = json.loads(result.stdout)
            return messages

        except Exception as e:
            print(f"WhatsApp poll error: {e}")
            return []

    def check_calendar_reminders(self) -> List[Dict]:
        """Check for upcoming calendar events that need reminders."""
        try:
            result = subprocess.run(
                [os.path.expanduser("~/.local/bin/gcal"), "list", "--upcoming", "15m", "--json"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return []

            events = json.loads(result.stdout)
            return events

        except Exception as e:
            print(f"Calendar check error: {e}")
            return []

    def process_email_event(self, email: Dict):
        """Process incoming email and log as event."""
        event_id = self.db.log_event(
            event_type="email_received",
            payload={
                "email_id": email["id"],
                "from": email["from"],
                "subject": email["subject"],
                "body_preview": email["body"][:500],
                "received_at": email["date"]
            }
        )

        # Check if this looks like a task/action request
        subject_lower = email["subject"].lower()
        if any(kw in subject_lower for kw in ["urgent", "action", "todo", "please", "asap"]):
            # Auto-create task from email
            self.db.add_task(
                content=f"[Email] {email['subject']} - from {email['from']}",
                priority=2 if "urgent" in subject_lower else 3,
                source="email",
                source_id=str(email["id"])
            )

        return event_id

    def process_whatsapp_event(self, message: Dict):
        """Process incoming WhatsApp message."""
        event_id = self.db.log_event(
            event_type="whatsapp_received",
            payload={
                "chat_id": message.get("chat_id"),
                "sender": message.get("sender"),
                "message": message.get("text", "")[:1000],
                "received_at": message.get("timestamp")
            }
        )
        return event_id

    def process_calendar_reminder(self, event: Dict):
        """Process upcoming calendar event."""
        event_id = self.db.log_event(
            event_type="calendar_reminder",
            payload={
                "event_id": event.get("id"),
                "summary": event.get("summary"),
                "start": event.get("start"),
                "location": event.get("location"),
                "minutes_until": event.get("minutes_until", 15)
            }
        )
        return event_id

    def run(self):
        """Main event loop."""
        print(f"Event monitor started. Polling every {self.poll_interval}s")

        while True:
            try:
                now = datetime.now().isoformat()

                # Poll email
                emails = self.poll_email()
                for email in emails:
                    self.process_email_event(email)
                    print(f"[{now}] New email from {email['from']}: {email['subject'][:50]}")

                # Poll WhatsApp
                messages = self.poll_whatsapp()
                for msg in messages:
                    self.process_whatsapp_event(msg)
                    print(f"[{now}] New WhatsApp from {msg.get('sender')}")

                # Check calendar
                upcoming = self.check_calendar_reminders()
                for event in upcoming:
                    self.process_calendar_reminder(event)
                    print(f"[{now}] Upcoming: {event.get('summary')}")

                # Check due reminders and task notifications
                due_reminders = self.db.get_due_reminders()
                for reminder in due_reminders:
                    self.db.log_event(
                        event_type="reminder_due",
                        payload={
                            "reminder_id": reminder["id"],
                            "task_id": reminder["task_id"],
                            "task_content": reminder["task_content"],
                            "channel": reminder["channel"]
                        }
                    )
                    print(f"[{now}] Reminder due: {reminder['task_content'][:50]}")

            except Exception as e:
                print(f"Event loop error: {e}")

            time.sleep(self.poll_interval)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--db", default="/var/lib/execwall/agent_memory.db")
    args = parser.parse_args()

    monitor = EventMonitor(poll_interval=args.interval, db_path=args.db)
    monitor.run()
```

**Step 2: Create systemd service**

```bash
# /etc/systemd/system/execwall-monitor.service
[Unit]
Description=Execwall Event Monitor
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/bin/python3 /usr/lib/execwall/agent/event_monitor.py --interval 30
Restart=always
RestartSec=10
Environment=PATH=/home/opc/.local/bin:/usr/local/bin:/usr/bin

[Install]
WantedBy=multi-user.target
```

**Step 3: Commit**

```bash
git add agent/event_monitor.py
git commit -m "feat: add event monitor daemon for WhatsApp/Email polling"
```

---

### Task 14: Create Proactive Notification System

**Files:**
- Create: `agent/notifier.py`
- Modify: `agent/main.py`

**Step 1: Write the notification handler**

```python
#!/usr/bin/env python3
# agent/notifier.py
"""
Proactive notification system - sends reminders via WhatsApp/Email.
Runs as part of the agent loop, not standalone.
"""
import json
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from tools.memory_db import MemoryDB

class Notifier:
    """Sends proactive notifications based on events and reminders."""

    def __init__(self, db_path: str = "/var/lib/execwall/agent_memory.db"):
        self.db = MemoryDB(db_path)

    def send_whatsapp(self, to: str, message: str) -> bool:
        """Send WhatsApp message via wa_send CLI."""
        try:
            result = subprocess.run(
                [
                    "/usr/local/bin/execwall", "--api-call",
                    json.dumps({
                        "tool": "wa_send",
                        "args": {"to": to, "message": message},
                        "identity": "notifier",
                        "approval_token": os.environ.get("EXECWALL_AUTO_APPROVAL_TOKEN")
                    })
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"WhatsApp send error: {e}")
            return False

    def send_email(self, to: str, subject: str, body: str) -> bool:
        """Send email via email_send CLI."""
        try:
            result = subprocess.run(
                [
                    "/usr/local/bin/execwall", "--api-call",
                    json.dumps({
                        "tool": "email_send",
                        "args": {"to": to, "subject": subject, "body": body},
                        "identity": "notifier",
                        "approval_token": os.environ.get("EXECWALL_AUTO_APPROVAL_TOKEN")
                    })
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Email send error: {e}")
            return False

    def process_due_reminders(self, default_recipient: str = "sundar"):
        """Process and send due reminders."""
        reminders = self.db.get_due_reminders()

        for reminder in reminders:
            message = f"🔔 Reminder: {reminder['task_content']}"

            if reminder["channel"] == "whatsapp":
                success = self.send_whatsapp(default_recipient, message)
            elif reminder["channel"] == "email":
                success = self.send_email(
                    default_recipient,
                    f"Reminder: {reminder['task_content'][:50]}",
                    message
                )
            else:
                success = False

            if success:
                self.db.mark_reminder_sent(reminder["id"])

    def notify_calendar_event(self, event: Dict, recipient: str = "sundar"):
        """Send notification for upcoming calendar event."""
        message = f"📅 Coming up in {event.get('minutes_until', 15)} minutes:\n"
        message += f"{event['summary']}"
        if event.get("location"):
            message += f"\n📍 {event['location']}"

        self.send_whatsapp(recipient, message)

    def daily_summary(self, recipient: str = "sundar"):
        """Send daily task summary."""
        tasks = self.db.get_pending_tasks(limit=10)

        if not tasks:
            return

        message = "📋 Today's Tasks:\n\n"
        for i, task in enumerate(tasks, 1):
            priority_emoji = {1: "🔴", 2: "🟠", 3: "🟡", 4: "🟢"}.get(task["priority"], "⚪")
            message += f"{priority_emoji} {i}. {task['content'][:60]}\n"

        if task.get("due_at"):
            message += f"   Due: {task['due_at']}\n"

        self.send_whatsapp(recipient, message)
```

**Step 2: Commit**

```bash
git add agent/notifier.py
git commit -m "feat: add proactive notification system"
```

---

## Phase 8: Fund Operations & Python Sandbox

### Task 15: Create Fund Monitoring Tools

**Files:**
- Create: `tools/fund_log_monitor.py`
- Create: `tools/fund_script_runner.py`
- Create: `fund_scripts/daily_check.py` (example)

**Step 1: Write log monitor tool**

```python
#!/usr/bin/env python3
# tools/fund_log_monitor.py
"""Monitor fund operation logs for anomalies."""
import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class FundLogMonitorTool(ToolBase):
    """Monitor fund logs for issues (read-only)."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "log_path": {
                "type": "string",
                "default": "/var/log/fund/operations.log"
            },
            "hours_back": {
                "type": "integer",
                "minimum": 1,
                "maximum": 168,  # 1 week
                "default": 24
            },
            "alert_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "default": ["ERROR", "CRITICAL", "FAILED", "EXCEPTION"]
            }
        }
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        log_path = request.params.get("log_path", "/var/log/fund/operations.log")
        hours_back = request.params.get("hours_back", 24)
        patterns = request.params.get("alert_patterns", ["ERROR", "CRITICAL"])

        try:
            if not os.path.exists(log_path):
                return ToolResponse(
                    success=True,
                    data={"alerts": [], "summary": "Log file not found"}
                )

            cutoff = datetime.now() - timedelta(hours=hours_back)
            alerts = []
            total_lines = 0
            pattern_re = re.compile("|".join(patterns), re.IGNORECASE)

            with open(log_path, "r") as f:
                for line in f:
                    total_lines += 1
                    if pattern_re.search(line):
                        alerts.append({
                            "line": line.strip()[:200],
                            "patterns_matched": [p for p in patterns if p.lower() in line.lower()]
                        })

            return ToolResponse(
                success=True,
                data={
                    "alerts": alerts[-50:],  # Last 50 alerts
                    "alert_count": len(alerts),
                    "lines_scanned": total_lines,
                    "hours_checked": hours_back,
                    "has_critical": any("CRITICAL" in a.get("patterns_matched", []) for a in alerts)
                }
            )

        except Exception as e:
            return ToolResponse(success=False, error=str(e))


if __name__ == "__main__":
    FundLogMonitorTool().main()
```

**Step 2: Write Python script runner (uses Execwall sandbox)**

```python
#!/usr/bin/env python3
# tools/fund_script_runner.py
"""Run fund Python scripts in Execwall sandbox."""
import json
import os
import subprocess
from typing import Any, Dict
from lib.tool_base import ToolBase, ToolRequest, ToolResponse

class FundScriptRunnerTool(ToolBase):
    """Run approved fund scripts in sandbox (requires approval)."""

    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "script_name": {
                "type": "string",
                "enum": [
                    "daily_check",
                    "position_summary",
                    "risk_report",
                    "pnl_snapshot"
                ],
                "description": "Name of approved script to run"
            },
            "params": {
                "type": "object",
                "description": "Script parameters"
            },
            "approval_token": {
                "type": "string"
            }
        },
        "required": ["script_name"]
    }

    SCRIPT_PATHS = {
        "daily_check": "/usr/lib/execwall/fund_scripts/daily_check.py",
        "position_summary": "/usr/lib/execwall/fund_scripts/position_summary.py",
        "risk_report": "/usr/lib/execwall/fund_scripts/risk_report.py",
        "pnl_snapshot": "/usr/lib/execwall/fund_scripts/pnl_snapshot.py",
    }

    def execute(self, request: ToolRequest) -> ToolResponse:
        script_name = request.params["script_name"]
        params = request.params.get("params", {})

        if script_name not in self.SCRIPT_PATHS:
            return ToolResponse(
                success=False,
                error=f"Unknown script: {script_name}"
            )

        script_path = self.SCRIPT_PATHS[script_name]

        # Execute through Execwall python_runner (sandboxed)
        try:
            with open(script_path, "r") as f:
                code = f.read()

            # Inject params as JSON
            code_with_params = f"__params__ = {json.dumps(params)}\n{code}"

            result = subprocess.run(
                [
                    "/usr/lib/execwall/python_runner",
                    "--profile", "fund_sandbox",
                    "--timeout", "60",
                    "--code", code_with_params
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            output = json.loads(result.stdout) if result.stdout else {}

            return ToolResponse(
                success=result.returncode == 0,
                data={
                    "script": script_name,
                    "output": output,
                    "stderr": result.stderr[:500] if result.stderr else None
                },
                error=result.stderr if result.returncode != 0 else None
            )

        except subprocess.TimeoutExpired:
            return ToolResponse(success=False, error="Script timeout exceeded")
        except Exception as e:
            return ToolResponse(success=False, error=str(e))


if __name__ == "__main__":
    FundScriptRunnerTool().main()
```

**Step 3: Add fund profiles to policy**

```yaml
# Add to policy-agent.yaml under profiles:
  fund_readonly:
    description: "Read-only fund monitoring"
    network:
      allow: false
    filesystem:
      read_allow:
        - "/var/log/fund"
        - "/var/lib/fund/data"
      write_allow:
        - "/work/out"
    limits:
      timeout_sec: 30
      mem_max_mb: 256

  fund_sandbox:
    description: "Sandboxed fund script execution"
    runner: "/usr/lib/execwall/python_runner"
    network:
      allow: true
      domains_allow:
        - "api.ibkr.com"
        - "*.interactivebrokers.com"
    filesystem:
      read_allow:
        - "/var/lib/fund/data"
        - "/usr/lib/execwall/fund_scripts"
      write_allow:
        - "/work/out"
        - "/tmp/fund_cache"
    limits:
      timeout_sec: 120
      mem_max_mb: 1024
      pids_max: 16
    require_approval: true
```

**Step 4: Commit**

```bash
git add tools/fund_log_monitor.py tools/fund_script_runner.py
git commit -m "feat: add fund monitoring and script runner tools"
```

---

## Phase 9: Security Architecture - Using Existing openclaw_launcher

### Task 16: Configure Seccomp Profile for Claude Agent

**We reuse the existing `openclaw_launcher` binary** - it already does everything needed:
- Loads seccomp profiles from policy.yaml
- Applies seccomp filter with libseccomp
- Sets SHELL to execwall-shell for command governance
- Blocks dangerous syscalls (fork, vfork, ptrace, mount, setuid, etc.)
- Execs ANY binary via `--openclaw-bin` flag

**Files:**
- Modify: `policy-agent.yaml` (add seccomp profile)
- Create: `scripts/start-claude-agent.sh`

**Step 1: Add seccomp profile to policy-agent.yaml**

```yaml
# Add to policy-agent.yaml under seccomp_profiles:
  agent_locked:
    # Extends gateway profile (allows network for API calls)
    extends: gateway

    # Block process creation
    deny:
      - fork
      - vfork
      - execveat

    # Block all dangerous syscalls
    deny_dangerous: true

    # Network restrictions - only Anthropic API and local Execwall
    network_policy:
      allow_outbound:
        - "api.anthropic.com:443"
        - "127.0.0.1:9999"
      block_metadata:
        - "169.254.169.254"  # AWS/cloud metadata
```

**Step 2: Create launch script**

```bash
#!/bin/bash
# scripts/start-claude-agent.sh
# Launch Claude Agent inside seccomp-locked environment using existing launcher

set -euo pipefail

POLICY="/etc/execwall/policy-agent.yaml"
AGENT_SCRIPT="/usr/lib/execwall/agent/main.py"
SECCOMP_PROFILE="agent_locked"

echo "Starting Claude Agent with Execwall security..."
echo "  Policy: $POLICY"
echo "  Seccomp profile: $SECCOMP_PROFILE"
echo ""

exec /usr/local/bin/openclaw_launcher \
    --openclaw-bin /usr/bin/python3 \
    --seccomp-profile "$SECCOMP_PROFILE" \
    --policy "$POLICY" \
    --execwall-repl \
    --verbose \
    -- "$AGENT_SCRIPT"
```

**Step 3: Create systemd service**

```ini
# /etc/systemd/system/claude-agent.service
[Unit]
Description=Claude Agent (Execwall Secured)
After=network.target execwall-monitor.service
Wants=execwall-monitor.service

[Service]
Type=simple
User=opc
Environment=ANTHROPIC_API_KEY=<from-secrets>
ExecStart=/usr/lib/execwall/scripts/start-claude-agent.sh
Restart=always
RestartSec=10

# Additional hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadOnlyPaths=/etc /usr
ReadWritePaths=/var/lib/execwall /var/log/execwall /work

[Install]
WantedBy=multi-user.target
```

**Step 4: Commit**

```bash
git add scripts/start-claude-agent.sh
git commit -m "feat: add Claude Agent launch script using existing openclaw_launcher"
```

**Security guarantees from existing launcher:**

| Protection | How It Works |
|------------|--------------|
| No subprocess spawning | Seccomp blocks fork/vfork/clone(CLONE_NEWPID) |
| No privilege escalation | Seccomp blocks setuid/setgid/setresuid |
| No filesystem escape | SHELL=execwall-shell governs all commands |
| No arbitrary exec | clone/execve blocked except for allowed paths |
| No debugging/tracing | ptrace blocked |
| Network restricted | Only api.anthropic.com:443 and localhost:9999 |

**Launch command (manual):**

```bash
# On Oracle instance:
openclaw_launcher \
  --openclaw-bin /usr/bin/python3 \
  --seccomp-profile agent_locked \
  --policy /etc/execwall/policy-agent.yaml \
  -- /usr/lib/execwall/agent/main.py
```

---

## Updated Tool Registry

| Tool | Profile | Privilege | Approval | Description |
|------|---------|-----------|----------|-------------|
| **Memory/Tasks** |
| task_add | tools_readonly | Low | No | Add task to list |
| task_list | tools_readonly | Low | No | List pending tasks |
| task_complete | tools_readonly | Low | No | Mark task done |
| remember | tools_readonly | Low | No | Store note |
| recall | tools_readonly | Low | No | Search memory |
| **Communication** |
| email_poll | tools_readonly | Low | No | Check new emails |
| wa_poll | tools_readonly | Low | No | Check new WhatsApp |
| email_send | tools_write | High | Yes | Send email |
| wa_send | tools_write | High | Yes | Send WhatsApp |
| slack_post | tools_write | High | Yes | Post to Slack |
| **Calendar** |
| cal_read | tools_readonly | Low | No | Read calendar |
| cal_create | tools_write | High | Yes | Create event |
| **Fund Operations** |
| fund_log_monitor | fund_readonly | Low | No | Monitor logs |
| fund_script_run | fund_sandbox | High | Yes | Run approved script |
| ib_status | tools_readonly | Low | No | IBKR account status |
| **Web** |
| web_search | tools_readonly | Low | No | Search web |
| browser_download | browser_automation | Very High | Yes | Download via browser |

---

## Summary: Complete Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     ORACLE CLOUD INSTANCE                         │
│                                                                    │
│  ┌────────────────────┐   ┌────────────────────────────────────┐ │
│  │ Event Monitor      │   │ Claude Agent (Seccomp-Locked)      │ │
│  │ (systemd service)  │   │                                    │ │
│  │                    │   │  ┌────────────────────────────┐   │ │
│  │ - Poll Email       │   │  │ Claude Agent SDK           │   │ │
│  │ - Poll WhatsApp    │   │  │ (talks to api.anthropic.com)│   │ │
│  │ - Check Calendar   │   │  └────────────┬───────────────┘   │ │
│  │ - Log events       │   │               │                    │ │
│  │                    │   │  ┌────────────▼───────────────┐   │ │
│  │                    │   │  │ ExecwallAgent Wrapper      │   │ │
│  │                    │   │  │ - Blocks shell/bash/exec   │   │ │
│  └─────────┬──────────┘   │  │ - Only calls execwall_run()│   │ │
│            │              │  └────────────┬───────────────┘   │ │
│            │              │               │                    │ │
│            │              └───────────────┼────────────────────┘ │
│            │                              │                       │
│            ▼                              ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                     SQLite Database                          │ │
│  │  - tasks, notes, events, reminders                           │ │
│  │  - /var/lib/execwall/agent_memory.db                         │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                     EXECWALL                                 │ │
│  │  - Policy enforcement (deny-by-default)                      │ │
│  │  - Profile selection (readonly, write, sandbox)              │ │
│  │  - Secrets injection (per-tool)                              │ │
│  │  - Audit logging                                             │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                              │                                    │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Tool Execution (Sandboxed)                      │ │
│  │                                                              │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │ │
│  │  │cal_read│ │wa_send │ │email_  │ │fund_   │ │web_    │   │ │
│  │  │        │ │(write) │ │send    │ │script  │ │search  │   │ │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │ │
│  │                                                              │ │
│  │  Each tool runs in isolated namespace with:                  │ │
│  │  - Seccomp syscall filter                                    │ │
│  │  - Cgroup resource limits                                    │ │
│  │  - Network restrictions                                      │ │
│  │  - Filesystem isolation                                      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

**Plan updated and saved.**

**Ready to execute. Choose:**

1. **Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks
2. **Parallel Session (separate)** - Open new session with executing-plans skill

---

## Phase 10: Autonomous Agent Core - AgentExW

This phase implements the autonomous agent loop with systemd watchdog support, enabling AgentExW to wake up periodically, monitor events, and take proactive actions.

### Task 17: Context Aggregator

**Files:**
- Create: `src/bin/agentexw_context.rs`
- Test: `tests/context_aggregator_test.rs`

**Step 1: Write the failing test**

```rust
// tests/context_aggregator_test.rs
use execwall::context::{ContextAggregator, ContextSnapshot};

#[test]
fn test_context_aggregator_collects_pending_tasks() {
    let aggregator = ContextAggregator::new("/var/lib/execwall/agent_memory.db");
    let ctx = aggregator.collect().unwrap();
    
    assert!(ctx.pending_tasks.is_some());
    assert!(ctx.timestamp.len() > 0);
}

#[test]
fn test_context_aggregator_collects_upcoming_calendar() {
    let aggregator = ContextAggregator::new("/var/lib/execwall/agent_memory.db");
    let ctx = aggregator.collect().unwrap();
    
    // Should have calendar entries for next 24 hours
    assert!(ctx.upcoming_events.is_some());
}

#[test]
fn test_context_aggregator_collects_unread_messages() {
    let aggregator = ContextAggregator::new("/var/lib/execwall/agent_memory.db");
    let ctx = aggregator.collect().unwrap();
    
    // Should check for unread WhatsApp and email
    assert!(ctx.unread_messages.is_some());
}
```

**Step 2: Write implementation**

```rust
// src/bin/agentexw_context.rs
//! AgentExW Context Aggregator
//! Collects all relevant context for agent decision-making

use chrono::{DateTime, Utc, Duration as ChronoDuration};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Snapshot of all relevant context for agent decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    pub timestamp: String,
    pub pending_tasks: Option<Vec<TaskItem>>,
    pub upcoming_events: Option<Vec<CalendarEvent>>,
    pub unread_messages: Option<Vec<UnreadMessage>>,
    pub overdue_reminders: Option<Vec<Reminder>>,
    pub recent_notes: Option<Vec<Note>>,
    pub fund_alerts: Option<Vec<FundAlert>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    pub id: i64,
    pub content: String,
    pub due: Option<String>,
    pub priority: i32,
    pub source: String,  // "manual", "email", "whatsapp"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub id: String,
    pub summary: String,
    pub start: String,
    pub end: String,
    pub minutes_until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreadMessage {
    pub source: String,  // "email", "whatsapp"
    pub from: String,
    pub preview: String,
    pub received_at: String,
    pub priority: String,  // "high", "normal", "low"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reminder {
    pub id: i64,
    pub content: String,
    pub due: String,
    pub minutes_overdue: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: i64,
    pub content: String,
    pub tags: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundAlert {
    pub alert_type: String,  // "log_anomaly", "script_failure", "threshold_breach"
    pub message: String,
    pub severity: String,
    pub timestamp: String,
}

pub struct ContextAggregator {
    db_path: String,
}

impl ContextAggregator {
    pub fn new(db_path: &str) -> Self {
        Self {
            db_path: db_path.to_string(),
        }
    }

    pub fn collect(&self) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
        let conn = Connection::open(&self.db_path)?;
        let now = Utc::now();
        
        Ok(ContextSnapshot {
            timestamp: now.to_rfc3339(),
            pending_tasks: Some(self.get_pending_tasks(&conn)?),
            upcoming_events: Some(self.get_upcoming_events()?),
            unread_messages: Some(self.get_unread_messages()?),
            overdue_reminders: Some(self.get_overdue_reminders(&conn)?),
            recent_notes: Some(self.get_recent_notes(&conn)?),
            fund_alerts: Some(self.get_fund_alerts()?),
        })
    }

    fn get_pending_tasks(&self, conn: &Connection) -> Result<Vec<TaskItem>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT id, content, due, priority, source 
             FROM tasks WHERE status = 'pending' 
             ORDER BY COALESCE(due, '9999-12-31'), priority DESC"
        )?;
        
        let rows = stmt.query_map([], |row| {
            Ok(TaskItem {
                id: row.get(0)?,
                content: row.get(1)?,
                due: row.get(2)?,
                priority: row.get(3)?,
                source: row.get(4)?,
            })
        })?;
        
        rows.collect()
    }

    fn get_upcoming_events(&self) -> Result<Vec<CalendarEvent>, Box<dyn std::error::Error>> {
        // Call cal_read tool via execwall
        let output = std::process::Command::new("execwall")
            .args(&["-c", "cal_read", "--json", "--hours", "24"])
            .output()?;
        
        if output.status.success() {
            let events: Vec<CalendarEvent> = serde_json::from_slice(&output.stdout)?;
            Ok(events)
        } else {
            Ok(vec![])
        }
    }

    fn get_unread_messages(&self) -> Result<Vec<UnreadMessage>, Box<dyn std::error::Error>> {
        let mut messages = vec![];
        
        // Check email via himalaya
        let email_output = std::process::Command::new("execwall")
            .args(&["-c", "email_check", "--json", "--unread"])
            .output()?;
        
        if email_output.status.success() {
            if let Ok(emails) = serde_json::from_slice::<Vec<UnreadMessage>>(&email_output.stdout) {
                messages.extend(emails);
            }
        }
        
        // Check WhatsApp (if configured)
        let wa_output = std::process::Command::new("execwall")
            .args(&["-c", "wa_check", "--json", "--unread"])
            .output()?;
        
        if wa_output.status.success() {
            if let Ok(wa_msgs) = serde_json::from_slice::<Vec<UnreadMessage>>(&wa_output.stdout) {
                messages.extend(wa_msgs);
            }
        }
        
        Ok(messages)
    }

    fn get_overdue_reminders(&self, conn: &Connection) -> Result<Vec<Reminder>, rusqlite::Error> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT id, content, due, 
                    CAST((julianday(?) - julianday(due)) * 24 * 60 AS INTEGER) as minutes_overdue
             FROM reminders 
             WHERE status = 'pending' AND due <= ?
             ORDER BY due"
        )?;
        
        let rows = stmt.query_map([&now, &now], |row| {
            Ok(Reminder {
                id: row.get(0)?,
                content: row.get(1)?,
                due: row.get(2)?,
                minutes_overdue: row.get(3)?,
            })
        })?;
        
        rows.collect()
    }

    fn get_recent_notes(&self, conn: &Connection) -> Result<Vec<Note>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT id, content, tags, created_at 
             FROM notes 
             ORDER BY created_at DESC LIMIT 10"
        )?;
        
        let rows = stmt.query_map([], |row| {
            Ok(Note {
                id: row.get(0)?,
                content: row.get(1)?,
                tags: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        
        rows.collect()
    }

    fn get_fund_alerts(&self) -> Result<Vec<FundAlert>, Box<dyn std::error::Error>> {
        // Check fund monitoring logs
        let output = std::process::Command::new("execwall")
            .args(&["-c", "fund_alerts", "--json", "--last-hour"])
            .output()?;
        
        if output.status.success() {
            let alerts: Vec<FundAlert> = serde_json::from_slice(&output.stdout).unwrap_or_default();
            Ok(alerts)
        } else {
            Ok(vec![])
        }
    }
}

fn main() {
    let aggregator = ContextAggregator::new("/var/lib/execwall/agent_memory.db");
    match aggregator.collect() {
        Ok(ctx) => {
            println!("{}", serde_json::to_string_pretty(&ctx).unwrap());
        }
        Err(e) => {
            eprintln!("Error collecting context: {}", e);
            std::process::exit(1);
        }
    }
}
```

---

### Task 18: Agent Decision Loop with Systemd Watchdog

**Files:**
- Create: `src/bin/agentexw.rs`
- Modify: `Cargo.toml`

**Step 1: Write the agent main loop**

```rust
// src/bin/agentexw.rs
//! AgentExW - Autonomous Agent with Execwall Security
//!
//! Main agent loop that:
//! 1. Wakes on timer or SIGUSR1
//! 2. Aggregates context (tasks, calendar, messages, alerts)
//! 3. Sends context to Claude for decision
//! 4. Executes approved actions via Execwall
//! 5. Notifies systemd watchdog
//! 6. Sleeps until next wake

use clap::Parser;
use nix::sys::signal::{self, Signal, SigHandler};
use sd_notify::NotifyState;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod context;
use context::{ContextAggregator, ContextSnapshot};

static WAKE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// AgentExW - Autonomous AI Agent with Execwall Security
#[derive(Parser, Debug)]
#[command(name = "agentexw")]
#[command(version)]
#[command(about = "Autonomous AI agent with deny-by-default security")]
struct Args {
    /// Path to policy configuration
    #[arg(long, default_value = "/etc/execwall/policy.yaml")]
    policy: String,

    /// Path to SQLite database for memory
    #[arg(long, default_value = "/var/lib/execwall/agent_memory.db")]
    db: String,

    /// Wake interval in seconds (0 = event-driven only)
    #[arg(long, default_value = "300")]
    interval: u64,

    /// Watchdog timeout in seconds (should match systemd WatchdogSec)
    #[arg(long, default_value = "60")]
    watchdog_sec: u64,

    /// Run once and exit (for testing)
    #[arg(long)]
    once: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Action decision from Claude
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentDecision {
    /// Whether to take action
    should_act: bool,
    /// Reasoning for the decision
    reasoning: String,
    /// Tool calls to execute (if should_act)
    tool_calls: Vec<ToolCallRequest>,
    /// Priority of action (1-5, 5 being urgent)
    priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolCallRequest {
    tool: String,
    args: serde_json::Value,
    requires_user_approval: bool,
}

extern "C" fn handle_sigusr1(_: i32) {
    WAKE_REQUESTED.store(true, Ordering::SeqCst);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set up SIGUSR1 handler for external wake requests
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1))?;
    }

    // Notify systemd that we're ready
    let _ = sd_notify::notify(true, &[NotifyState::Ready]);
    log(&args, "AgentExW started");

    // Initialize components
    let context_aggregator = ContextAggregator::new(&args.db);
    let watchdog_interval = Duration::from_secs(args.watchdog_sec / 2);
    let wake_interval = Duration::from_secs(args.interval);
    
    let mut last_wake = Instant::now();
    let mut last_watchdog = Instant::now();

    loop {
        // Pet the watchdog regularly
        if last_watchdog.elapsed() >= watchdog_interval {
            let _ = sd_notify::notify(true, &[NotifyState::Watchdog]);
            last_watchdog = Instant::now();
        }

        // Check if we should wake
        let should_wake = WAKE_REQUESTED.swap(false, Ordering::SeqCst)
            || (args.interval > 0 && last_wake.elapsed() >= wake_interval);

        if should_wake || args.once {
            log(&args, "Waking up - collecting context");
            last_wake = Instant::now();

            // Collect context
            let context = match context_aggregator.collect() {
                Ok(ctx) => ctx,
                Err(e) => {
                    log(&args, &format!("Error collecting context: {}", e));
                    if args.once { break; }
                    continue;
                }
            };

            // Determine if action is needed
            if should_act(&context) {
                log(&args, "Context requires action - consulting Claude");
                
                // Get decision from Claude via execwall-protected API
                match get_agent_decision(&context, &args.policy) {
                    Ok(decision) => {
                        log(&args, &format!("Decision: {} (priority {})", 
                            if decision.should_act { "ACT" } else { "WAIT" },
                            decision.priority
                        ));

                        if decision.should_act {
                            execute_decision(&decision, &args);
                        }
                    }
                    Err(e) => {
                        log(&args, &format!("Error getting decision: {}", e));
                    }
                }
            } else {
                log(&args, "No action required - context is clear");
            }

            if args.once {
                break;
            }
        }

        // Sleep briefly to avoid busy loop
        std::thread::sleep(Duration::from_millis(100));
    }

    // Notify systemd we're stopping
    let _ = sd_notify::notify(true, &[NotifyState::Stopping]);
    log(&args, "AgentExW stopped");
    Ok(())
}

/// Quick check if context warrants consulting Claude
fn should_act(context: &ContextSnapshot) -> bool {
    // Act if there are overdue reminders
    if let Some(ref reminders) = context.overdue_reminders {
        if !reminders.is_empty() {
            return true;
        }
    }

    // Act if there are unread high-priority messages
    if let Some(ref messages) = context.unread_messages {
        if messages.iter().any(|m| m.priority == "high") {
            return true;
        }
    }

    // Act if there are upcoming events within 15 minutes
    if let Some(ref events) = context.upcoming_events {
        if events.iter().any(|e| e.minutes_until <= 15 && e.minutes_until >= 0) {
            return true;
        }
    }

    // Act if there are fund alerts
    if let Some(ref alerts) = context.fund_alerts {
        if !alerts.is_empty() {
            return true;
        }
    }

    // Otherwise, only act on periodic interval with pending tasks
    if let Some(ref tasks) = context.pending_tasks {
        return !tasks.is_empty();
    }

    false
}

/// Get decision from Claude via Execwall-protected API
fn get_agent_decision(context: &ContextSnapshot, policy: &str) -> Result<AgentDecision, Box<dyn std::error::Error>> {
    let system_prompt = r#"You are AgentExW, an autonomous AI assistant with strict security boundaries.

Your role is to:
1. Review the provided context (tasks, calendar, messages, alerts)
2. Decide if any action is needed NOW
3. If action is needed, specify which tools to call

Security rules:
- You can ONLY call tools that are defined in the policy
- Write operations (sending messages, creating events) require user approval unless marked urgent
- Never execute shell commands directly - only call defined tools
- Never access files outside allowed paths

Respond with a JSON AgentDecision object."#;

    let user_prompt = format!(
        "Current context:\n```json\n{}\n```\n\nWhat action, if any, should be taken?",
        serde_json::to_string_pretty(context)?
    );

    // Call Claude via execwall-protected endpoint
    let request = serde_json::json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_prompt}
        ]
    });

    let output = std::process::Command::new("execwall")
        .args(&["--policy", policy, "-c", "claude_api", "--json"])
        .env("REQUEST", serde_json::to_string(&request)?)
        .output()?;

    if output.status.success() {
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        // Extract the decision from Claude's response
        if let Some(text) = response.get("content").and_then(|c| c.get(0)).and_then(|t| t.get("text")).and_then(|t| t.as_str()) {
            // Parse JSON from response
            let decision: AgentDecision = serde_json::from_str(text)?;
            return Ok(decision);
        }
    }

    // Default: no action
    Ok(AgentDecision {
        should_act: false,
        reasoning: "Failed to get Claude response".to_string(),
        tool_calls: vec![],
        priority: 0,
    })
}

/// Execute the agent's decision via Execwall
fn execute_decision(decision: &AgentDecision, args: &Args) {
    for call in &decision.tool_calls {
        log(args, &format!("Executing: {} (approval: {})", 
            call.tool, 
            if call.requires_user_approval { "required" } else { "auto" }
        ));

        // Check if user approval is required
        if call.requires_user_approval && decision.priority < 5 {
            // Store pending approval request
            log(args, &format!("Queuing {} for user approval", call.tool));
            queue_for_approval(&call);
            continue;
        }

        // Execute via Execwall
        let result = std::process::Command::new("execwall")
            .args(&["--policy", &args.policy, "-c", &call.tool, "--json"])
            .env("ARGS", serde_json::to_string(&call.args).unwrap_or_default())
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    log(args, &format!("Tool {} succeeded", call.tool));
                } else {
                    log(args, &format!("Tool {} failed: {}", 
                        call.tool, 
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            Err(e) => {
                log(args, &format!("Failed to execute {}: {}", call.tool, e));
            }
        }
    }
}

fn queue_for_approval(call: &ToolCallRequest) {
    // Store in SQLite for user to approve via CLI
    // User runs: agentexw --approve <id> or agentexw --deny <id>
    let _ = std::process::Command::new("sqlite3")
        .args(&[
            "/var/lib/execwall/agent_memory.db",
            &format!(
                "INSERT INTO pending_approvals (tool, args, created_at) VALUES ('{}', '{}', datetime('now'))",
                call.tool,
                serde_json::to_string(&call.args).unwrap_or_default().replace('\'', "''")
            )
        ])
        .output();
}

fn log(args: &Args, msg: &str) {
    if args.verbose || std::env::var("JOURNAL_STREAM").is_ok() {
        eprintln!("[AgentExW] {}", msg);
    }
}
```

**Step 2: Add dependencies to Cargo.toml**

```toml
[dependencies]
sd-notify = "0.4"
nix = { version = "0.28", features = ["signal"] }
```

---

### Task 19: Systemd Services with Watchdog

**Files:**
- Create: `systemd/agentexw.service`
- Create: `systemd/agentexw-watcher.service`
- Create: `systemd/agentexw-watcher.path`

**Step 1: Create main agent service**

```ini
# systemd/agentexw.service
[Unit]
Description=AgentExW - Autonomous AI Agent with Execwall Security
Documentation=https://github.com/sundarsub/execwall
After=network.target
Wants=agentexw-watcher.path

[Service]
Type=notify
ExecStart=/usr/local/bin/agentexw --policy /etc/execwall/policy.yaml --db /var/lib/execwall/agent_memory.db --interval 300
ExecReload=/bin/kill -USR1 $MAINPID

# Watchdog - service must call sd_notify(WATCHDOG) within this interval
WatchdogSec=60
# Restart if watchdog fails
Restart=on-watchdog
# Also restart on failure
RestartSec=10

# Security hardening
User=execwall
Group=execwall
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/execwall /var/log/execwall
ReadOnlyPaths=/etc/execwall

# Resource limits
MemoryMax=512M
CPUQuota=50%
TasksMax=64

# Environment
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

**Step 2: Create watcher service for event-driven wakeup**

```ini
# systemd/agentexw-watcher.service
[Unit]
Description=AgentExW Event Watcher - Triggers agent on new events
After=agentexw.service
BindsTo=agentexw.service

[Service]
Type=oneshot
ExecStart=/bin/kill -USR1 $(cat /run/agentexw.pid)

[Install]
WantedBy=multi-user.target
```

**Step 3: Create path unit for file-based triggers**

```ini
# systemd/agentexw-watcher.path
[Unit]
Description=Watch for AgentExW trigger events
After=agentexw.service
BindsTo=agentexw.service

[Path]
# Watch for new WhatsApp messages
PathChanged=/var/lib/execwall/events/whatsapp
# Watch for new emails
PathChanged=/var/lib/execwall/events/email
# Watch for fund alerts
PathChanged=/var/lib/execwall/events/fund_alerts
# Watch for manual trigger
PathExists=/var/lib/execwall/events/wake

[Install]
WantedBy=multi-user.target
```

**Step 4: Create timer for scheduled checks**

```ini
# systemd/agentexw-scheduled.timer
[Unit]
Description=Scheduled AgentExW wake-up timer
After=agentexw.service

[Timer]
OnCalendar=*:0/5
# Also wake at specific times for daily review
OnCalendar=*-*-* 08:00:00
OnCalendar=*-*-* 20:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

---

### Task 20: Installation Script

**Files:**
- Create: `scripts/install-agentexw.sh`

```bash
#!/bin/bash
# AgentExW Installation Script
set -e

INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/lib/execwall"
CONFIG_DIR="/etc/execwall"
DATA_DIR="/var/lib/execwall"
LOG_DIR="/var/log/execwall"

echo "Installing AgentExW..."

# Create directories
sudo mkdir -p "$LIB_DIR" "$CONFIG_DIR" "$DATA_DIR/events" "$LOG_DIR"

# Create execwall user if not exists
if ! id -u execwall &>/dev/null; then
    sudo useradd -r -s /bin/false -d "$DATA_DIR" execwall
fi

# Build binaries
cargo build --release

# Install binaries
sudo cp target/release/agentexw "$INSTALL_DIR/"
sudo cp target/release/execwall "$INSTALL_DIR/"
sudo cp target/release/python_runner "$LIB_DIR/"

# Install policy if not exists
if [ ! -f "$CONFIG_DIR/policy.yaml" ]; then
    sudo cp config/policy.yaml "$CONFIG_DIR/"
fi

# Initialize SQLite database
if [ ! -f "$DATA_DIR/agent_memory.db" ]; then
    sqlite3 "$DATA_DIR/agent_memory.db" << 'SQL'
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT,
    priority INTEGER DEFAULT 0,
    source TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    tags TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    notified_at TEXT
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    decided_at TEXT,
    decision TEXT
);

CREATE TABLE IF NOT EXISTS execution_log (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT,
    result TEXT,
    exit_code INTEGER,
    executed_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_reminders_status ON reminders(status, due);
CREATE INDEX idx_pending_approvals_status ON pending_approvals(status);
SQL
fi

# Set permissions
sudo chown -R execwall:execwall "$DATA_DIR" "$LOG_DIR"
sudo chmod 750 "$DATA_DIR" "$LOG_DIR"

# Install systemd services
sudo cp systemd/agentexw.service /etc/systemd/system/
sudo cp systemd/agentexw-watcher.service /etc/systemd/system/
sudo cp systemd/agentexw-watcher.path /etc/systemd/system/
sudo cp systemd/agentexw-scheduled.timer /etc/systemd/system/

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable agentexw.service
sudo systemctl enable agentexw-watcher.path
sudo systemctl enable agentexw-scheduled.timer

echo "AgentExW installed successfully!"
echo ""
echo "To start:"
echo "  sudo systemctl start agentexw"
echo ""
echo "To view logs:"
echo "  journalctl -u agentexw -f"
echo ""
echo "To trigger wake manually:"
echo "  touch /var/lib/execwall/events/wake"
echo "  # or: systemctl reload agentexw"
```

---

### Task 21: CLI Control Interface

**Files:**
- Modify: `src/bin/agentexw.rs` (add subcommands)

**Add CLI subcommands for agent control:**

```rust
// Add to Args enum using clap subcommands
#[derive(Parser, Debug)]
#[command(name = "agentexw")]
#[command(version)]
#[command(about = "AgentExW - Autonomous AI Agent with Execwall Security")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to policy configuration
    #[arg(long, default_value = "/etc/execwall/policy.yaml", global = true)]
    policy: String,

    /// Path to SQLite database
    #[arg(long, default_value = "/var/lib/execwall/agent_memory.db", global = true)]
    db: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the agent daemon (default)
    Run {
        #[arg(long, default_value = "300")]
        interval: u64,
        #[arg(long, default_value = "60")]
        watchdog_sec: u64,
        #[arg(long)]
        once: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// List pending approval requests
    Pending,
    /// Approve a pending action
    Approve {
        id: i64,
    },
    /// Deny a pending action
    Deny {
        id: i64,
    },
    /// Add a task
    Task {
        content: String,
        #[arg(long)]
        due: Option<String>,
        #[arg(long, default_value = "0")]
        priority: i32,
    },
    /// Add a reminder
    Remind {
        content: String,
        due: String,
    },
    /// Add a note
    Note {
        content: String,
        #[arg(long)]
        tags: Option<String>,
    },
    /// Show status
    Status,
    /// Wake the agent now
    Wake,
    /// Show recent execution log
    Log {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

// Implementation for subcommands
fn handle_pending(db: &str) -> Result<(), Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(db)?;
    let mut stmt = conn.prepare(
        "SELECT id, tool, args, created_at FROM pending_approvals WHERE status = 'pending'"
    )?;
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    println!("Pending approvals:");
    for row in rows {
        let (id, tool, args, created) = row?;
        println!("  [{}] {} - {} ({})", id, tool, args, created);
    }
    Ok(())
}

fn handle_approve(db: &str, id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(db)?;
    
    // Get the pending action
    let (tool, args): (String, String) = conn.query_row(
        "SELECT tool, args FROM pending_approvals WHERE id = ? AND status = 'pending'",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?))
    )?;

    // Execute it
    println!("Executing: {} with args: {}", tool, args);
    let output = std::process::Command::new("execwall")
        .args(&["-c", &tool, "--json"])
        .env("ARGS", &args)
        .output()?;

    // Update status
    conn.execute(
        "UPDATE pending_approvals SET status = 'approved', decided_at = datetime('now') WHERE id = ?",
        [id]
    )?;

    if output.status.success() {
        println!("Approved and executed successfully");
    } else {
        println!("Approved but execution failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn handle_deny(db: &str, id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(db)?;
    conn.execute(
        "UPDATE pending_approvals SET status = 'denied', decided_at = datetime('now') WHERE id = ?",
        [id]
    )?;
    println!("Denied action {}", id);
    Ok(())
}

fn handle_status(db: &str) -> Result<(), Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(db)?;
    
    let pending_tasks: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tasks WHERE status = 'pending'", [], |r| r.get(0)
    )?;
    let pending_approvals: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'", [], |r| r.get(0)
    )?;
    let overdue_reminders: i64 = conn.query_row(
        "SELECT COUNT(*) FROM reminders WHERE status = 'pending' AND due <= datetime('now')", [], |r| r.get(0)
    )?;

    println!("AgentExW Status:");
    println!("  Pending tasks: {}", pending_tasks);
    println!("  Pending approvals: {}", pending_approvals);
    println!("  Overdue reminders: {}", overdue_reminders);

    // Check if service is running
    let status = std::process::Command::new("systemctl")
        .args(&["is-active", "agentexw"])
        .output();
    
    if let Ok(out) = status {
        let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("  Service status: {}", state);
    }

    Ok(())
}

fn handle_wake() -> Result<(), Box<dyn std::error::Error>> {
    // Touch the wake file to trigger path unit
    std::fs::write("/var/lib/execwall/events/wake", "")?;
    // Also send SIGUSR1 directly if we have the PID
    let _ = std::process::Command::new("systemctl")
        .args(&["reload", "agentexw"])
        .output();
    println!("Wake signal sent to AgentExW");
    Ok(())
}
```

---

### Phase 10 Summary

| Task | Description | Dependencies |
|------|-------------|--------------|
| 17 | Context Aggregator | SQLite schema |
| 18 | Agent Decision Loop | Context Aggregator, Execwall |
| 19 | Systemd Services | Agent binary |
| 20 | Installation Script | All components |
| 21 | CLI Control Interface | SQLite schema |

**Key Features:**
- **Systemd Type=notify**: Agent notifies systemd it's ready
- **WatchdogSec**: Systemd kills and restarts if agent hangs
- **SIGUSR1 wake**: External events can trigger immediate wake
- **Path units**: File-based event triggers (WhatsApp, email, alerts)
- **Approval queue**: Write operations stored for user review
- **CLI control**: `agentexw status`, `agentexw approve 1`, `agentexw wake`

**Security guarantees remain intact:**
- All tool execution goes through Execwall
- Policy-based deny-by-default
- Approval required for write operations
- Audit logging of all actions
- Resource limits via cgroups


---

## Phase 11: User Isolation and Message Channels

This phase adds proper user isolation so AgentExW maintains separate context per user and only responds to allowed users.

### Task 22: User Model and Isolation

**Files:**
- Modify: `scripts/install-agentexw.sh` (SQLite schema)
- Create: `src/user.rs`

**SQLite Schema with User Isolation:**

```sql
-- Users table (from policy allowlist)
CREATE TABLE users (
    id TEXT PRIMARY KEY,           -- "sundar", "alice"
    phone TEXT UNIQUE,             -- "+16468259551"
    email TEXT UNIQUE,             -- "sundar@example.com"
    display_name TEXT,
    allowed INTEGER DEFAULT 1,     -- 0 = blocked, 1 = allowed
    created_at TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT
);

-- All user-scoped tables have user_id FK
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    due TEXT,
    priority INTEGER DEFAULT 0,
    source TEXT DEFAULT 'manual',  -- "whatsapp", "email", "manual"
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);
CREATE INDEX idx_tasks_user ON tasks(user_id, status);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    tags TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_notes_user ON notes(user_id);

CREATE TABLE reminders (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    due TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    notified_at TEXT
);
CREATE INDEX idx_reminders_user ON reminders(user_id, status);

-- Conversation history per user (for context)
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    channel TEXT NOT NULL,         -- "whatsapp", "email"
    role TEXT NOT NULL,            -- "user", "assistant"
    content TEXT NOT NULL,
    message_id TEXT,               -- external message ID
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_convos_user ON conversations(user_id, created_at);

-- Pending approvals are also user-scoped
CREATE TABLE pending_approvals (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    tool TEXT NOT NULL,
    args TEXT,
    reason TEXT,                   -- why agent wants to do this
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    decided_at TEXT,
    decision TEXT
);
CREATE INDEX idx_approvals_user ON pending_approvals(user_id, status);

-- Execution log (audit trail per user)
CREATE TABLE execution_log (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    tool TEXT NOT NULL,
    args TEXT,
    result TEXT,
    exit_code INTEGER,
    executed_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_execlog_user ON execution_log(user_id);
```

**User Resolution Logic (`src/user.rs`):**

```rust
// src/user.rs
//! User management with isolation guarantees

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub allowed: bool,
}

pub struct UserManager {
    db_path: String,
}

impl UserManager {
    pub fn new(db_path: &str) -> Self {
        Self { db_path: db_path.to_string() }
    }

    /// Resolve user from phone number (WhatsApp)
    pub fn resolve_from_phone(&self, phone: &str) -> Result<Option<User>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, phone, email, display_name, allowed FROM users WHERE phone = ?"
        )?;
        
        stmt.query_row([phone], |row| {
            Ok(User {
                id: row.get(0)?,
                phone: row.get(1)?,
                email: row.get(2)?,
                display_name: row.get(3)?,
                allowed: row.get::<_, i32>(4)? == 1,
            })
        }).optional()
    }

    /// Resolve user from email address
    pub fn resolve_from_email(&self, email: &str) -> Result<Option<User>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, phone, email, display_name, allowed FROM users WHERE email = ?"
        )?;
        
        stmt.query_row([email], |row| {
            Ok(User {
                id: row.get(0)?,
                phone: row.get(1)?,
                email: row.get(2)?,
                display_name: row.get(3)?,
                allowed: row.get::<_, i32>(4)? == 1,
            })
        }).optional()
    }

    /// Check if user is allowed (returns false for unknown users)
    pub fn is_allowed_phone(&self, phone: &str) -> bool {
        self.resolve_from_phone(phone)
            .ok()
            .flatten()
            .map(|u| u.allowed)
            .unwrap_or(false)
    }

    pub fn is_allowed_email(&self, email: &str) -> bool {
        self.resolve_from_email(email)
            .ok()
            .flatten()
            .map(|u| u.allowed)
            .unwrap_or(false)
    }

    /// Update last seen timestamp
    pub fn touch(&self, user_id: &str) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "UPDATE users SET last_seen_at = datetime('now') WHERE id = ?",
            [user_id]
        )?;
        Ok(())
    }

    /// Sync users from policy.yaml allowlist
    pub fn sync_from_policy(&self, allowed_users: &[PolicyUser]) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        
        for user in allowed_users {
            conn.execute(
                "INSERT INTO users (id, phone, email, display_name, allowed)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(id) DO UPDATE SET
                   phone = ?2, email = ?3, display_name = ?4, allowed = 1",
                [&user.id, &user.phone.as_deref().unwrap_or(""), 
                 &user.email.as_deref().unwrap_or(""), &user.display_name.as_deref().unwrap_or("")]
            )?;
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyUser {
    pub id: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}
```

---

### Task 23: Policy AllowList Configuration

**Add to `policy.yaml`:**

```yaml
# User allowlist - only these users can interact with AgentExW
# Unknown senders are silently ignored (no response)
allowed_users:
  - id: "sundar"
    phone: "+16468259551"
    email: "sundar@example.com"
    display_name: "Sundar"
  
  - id: "alice"
    phone: "+1234567890"
    email: "alice@company.com"
    display_name: "Alice"

# Channel-specific settings
channels:
  whatsapp:
    enabled: true
    # Reuse OpenClaw's WhatsApp connection
    credentials_path: "~/.openclaw/credentials/whatsapp"
    # Max context messages to include
    context_window: 20
    # Debounce rapid messages (ms)
    debounce_ms: 1000
    
  email:
    enabled: true
    # Use himalaya for IMAP/SMTP
    config_path: "~/.config/himalaya/config.toml"
    account: "default"
    # Only process emails from allowed users
    check_interval_sec: 60
    # Max emails to fetch per check
    max_fetch: 10
    context_window: 10
```

---

### Task 24: Message Listener Service

**Files:**
- Create: `src/bin/agentexw_listener.rs`
- Create: `systemd/agentexw-listener.service`

**WhatsApp/Email Listener:**

```rust
// src/bin/agentexw_listener.rs
//! AgentExW Message Listener
//! 
//! Monitors WhatsApp and Email for new messages from allowed users.
//! Writes events to /var/lib/execwall/events/ to wake AgentExW.
//! Maintains conversation context per user.

use clap::Parser;
use notify::{Watcher, RecursiveMode, Event};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod user;
use user::UserManager;

#[derive(Parser, Debug)]
#[command(name = "agentexw-listener")]
struct Args {
    #[arg(long, default_value = "/etc/execwall/policy.yaml")]
    policy: String,
    
    #[arg(long, default_value = "/var/lib/execwall/agent_memory.db")]
    db: String,
    
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Serialize)]
struct IncomingMessage {
    user_id: String,
    channel: String,      // "whatsapp" or "email"
    from: String,         // phone or email address
    content: String,
    message_id: String,
    timestamp: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let user_manager = UserManager::new(&args.db);
    let mut debounce_map: HashMap<String, Instant> = HashMap::new();
    let debounce_duration = Duration::from_millis(1000);
    
    // Watch OpenClaw's WhatsApp session file for changes
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?;
    
    // Watch OpenClaw session directory
    let wa_sessions = std::env::var("HOME").unwrap_or_default() + "/.openclaw/agents/main/sessions";
    watcher.watch(Path::new(&wa_sessions), RecursiveMode::NonRecursive)?;
    
    log(&args, &format!("Watching WhatsApp sessions at {}", wa_sessions));
    
    // Also poll email periodically
    let email_check_interval = Duration::from_secs(60);
    let mut last_email_check = Instant::now();
    
    loop {
        // Check for WhatsApp file changes
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                if let Some(path) = event.paths.first() {
                    if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                        // Parse new WhatsApp message
                        if let Some(msg) = parse_whatsapp_message(path, &user_manager) {
                            // Debounce
                            let key = format!("{}:{}", msg.channel, msg.from);
                            if let Some(last) = debounce_map.get(&key) {
                                if last.elapsed() < debounce_duration {
                                    continue;
                                }
                            }
                            debounce_map.insert(key, Instant::now());
                            
                            // Check if user is allowed
                            if !user_manager.is_allowed_phone(&msg.from) {
                                log(&args, &format!("Ignoring message from unknown: {}", msg.from));
                                continue;
                            }
                            
                            // Store in conversation history
                            store_message(&args.db, &msg)?;
                            
                            // Write event to wake AgentExW
                            write_event("whatsapp", &msg)?;
                            
                            log(&args, &format!("New WhatsApp from {}: {}", 
                                msg.user_id, truncate(&msg.content, 50)));
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => {
                log(&args, &format!("Watch error: {}", e));
            }
        }
        
        // Periodic email check
        if last_email_check.elapsed() >= email_check_interval {
            last_email_check = Instant::now();
            
            if let Ok(emails) = check_new_emails(&args, &user_manager) {
                for msg in emails {
                    store_message(&args.db, &msg)?;
                    write_event("email", &msg)?;
                    log(&args, &format!("New email from {}: {}", 
                        msg.user_id, truncate(&msg.content, 50)));
                }
            }
        }
    }
}

fn parse_whatsapp_message(session_path: &Path, user_mgr: &UserManager) -> Option<IncomingMessage> {
    // Read last line of JSONL session file
    let content = std::fs::read_to_string(session_path).ok()?;
    let last_line = content.lines().last()?;
    
    let entry: serde_json::Value = serde_json::from_str(last_line).ok()?;
    
    // Check if it's a user message (not assistant)
    if entry.get("role")?.as_str()? != "user" {
        return None;
    }
    
    let from = entry.get("from")?.as_str()?;
    let content = entry.get("content")?.as_str()?;
    
    // Resolve user
    let user = user_mgr.resolve_from_phone(from).ok()??;
    
    Some(IncomingMessage {
        user_id: user.id,
        channel: "whatsapp".to_string(),
        from: from.to_string(),
        content: content.to_string(),
        message_id: entry.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

fn check_new_emails(args: &Args, user_mgr: &UserManager) -> Result<Vec<IncomingMessage>, Box<dyn std::error::Error>> {
    let mut messages = vec![];
    
    // Use himalaya to check for new emails
    let output = std::process::Command::new("himalaya")
        .args(&["envelope", "list", "-f", "INBOX", "-w", "10", "-o", "json"])
        .output()?;
    
    if !output.status.success() {
        return Ok(messages);
    }
    
    let envelopes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    
    for env in envelopes {
        let from = env.get("from").and_then(|f| f.as_str()).unwrap_or("");
        let subject = env.get("subject").and_then(|s| s.as_str()).unwrap_or("");
        let id = env.get("id").and_then(|i| i.as_str()).unwrap_or("");
        
        // Extract email address from "Name <email>" format
        let email_addr = extract_email(from);
        
        // Check if from allowed user
        if let Some(user) = user_mgr.resolve_from_email(&email_addr).ok().flatten() {
            if user.allowed {
                messages.push(IncomingMessage {
                    user_id: user.id,
                    channel: "email".to_string(),
                    from: email_addr,
                    content: subject.to_string(), // Just subject for now
                    message_id: id.to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }
    
    Ok(messages)
}

fn store_message(db_path: &str, msg: &IncomingMessage) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "INSERT INTO conversations (user_id, channel, role, content, message_id)
         VALUES (?1, ?2, 'user', ?3, ?4)",
        [&msg.user_id, &msg.channel, &msg.content, &msg.message_id]
    )?;
    Ok(())
}

fn write_event(channel: &str, msg: &IncomingMessage) -> Result<(), std::io::Error> {
    let event_dir = "/var/lib/execwall/events";
    std::fs::create_dir_all(event_dir)?;
    
    let event_file = format!("{}/{}", event_dir, channel);
    let event_data = serde_json::to_string(msg)?;
    
    std::fs::write(&event_file, &event_data)?;
    Ok(())
}

fn extract_email(from: &str) -> String {
    // "Name <email@example.com>" -> "email@example.com"
    if let Some(start) = from.find('<') {
        if let Some(end) = from.find('>') {
            return from[start+1..end].to_string();
        }
    }
    from.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
}

fn log(args: &Args, msg: &str) {
    if args.verbose {
        eprintln!("[listener] {}", msg);
    }
}
```

**Systemd Service:**

```ini
# systemd/agentexw-listener.service
[Unit]
Description=AgentExW Message Listener
After=network.target openclaw.service
Wants=agentexw.service

[Service]
Type=simple
ExecStart=/usr/local/bin/agentexw-listener --policy /etc/execwall/policy.yaml --db /var/lib/execwall/agent_memory.db
Restart=always
RestartSec=5

User=execwall
Group=execwall

[Install]
WantedBy=multi-user.target
```

---

### Task 25: Context-Aware Response Generation

**Modify agent decision loop to include user context:**

```rust
// In agentexw.rs - modify get_agent_decision to include user context

fn get_user_context(db_path: &str, user_id: &str, limit: usize) -> Vec<ConversationMessage> {
    let conn = Connection::open(db_path).ok();
    if conn.is_none() {
        return vec![];
    }
    let conn = conn.unwrap();
    
    let mut stmt = conn.prepare(
        "SELECT role, content, channel, created_at 
         FROM conversations 
         WHERE user_id = ?
         ORDER BY created_at DESC 
         LIMIT ?"
    ).ok();
    
    if stmt.is_none() {
        return vec![];
    }
    let mut stmt = stmt.unwrap();
    
    let rows = stmt.query_map([user_id, &limit.to_string()], |row| {
        Ok(ConversationMessage {
            role: row.get(0)?,
            content: row.get(1)?,
            channel: row.get(2)?,
            timestamp: row.get(3)?,
        })
    });
    
    rows.ok()
        .map(|r| r.filter_map(|m| m.ok()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .rev()  // Chronological order
        .collect()
}

fn build_user_prompt(context: &ContextSnapshot, user_id: &str, db_path: &str) -> String {
    let history = get_user_context(db_path, user_id, 20);
    
    let history_str = history.iter()
        .map(|m| format!("[{}] {}: {}", m.channel, m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n");
    
    format!(r#"
User: {}

Recent conversation:
{}

Current context:
```json
{}
```

What action should be taken for this user?
"#, 
        user_id,
        history_str,
        serde_json::to_string_pretty(context).unwrap_or_default()
    )
}
```

---

### Task 26: Send Response Back to User

**Add response sending via WhatsApp/Email:**

```rust
// src/response.rs
//! Send responses back to users via their preferred channel

use crate::user::User;

pub struct ResponseSender {
    policy_path: String,
}

impl ResponseSender {
    pub fn new(policy_path: &str) -> Self {
        Self { policy_path: policy_path.to_string() }
    }

    /// Send response to user via their last active channel
    pub fn send(&self, user: &User, channel: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        match channel {
            "whatsapp" => self.send_whatsapp(user, message),
            "email" => self.send_email(user, message),
            _ => Err("Unknown channel".into()),
        }
    }

    fn send_whatsapp(&self, user: &User, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let phone = user.phone.as_ref().ok_or("User has no phone")?;
        
        // Use execwall to send via wa_send tool
        let output = std::process::Command::new("execwall")
            .args(&["--policy", &self.policy_path, "-c", "wa_send"])
            .env("WA_TO", phone)
            .env("WA_MESSAGE", message)
            .output()?;
        
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("wa_send failed: {}", String::from_utf8_lossy(&output.stderr)).into())
        }
    }

    fn send_email(&self, user: &User, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let email = user.email.as_ref().ok_or("User has no email")?;
        
        // Use execwall to send via email_send tool
        let output = std::process::Command::new("execwall")
            .args(&["--policy", &self.policy_path, "-c", "email_send"])
            .env("EMAIL_TO", email)
            .env("EMAIL_BODY", message)
            .output()?;
        
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("email_send failed: {}", String::from_utf8_lossy(&output.stderr)).into())
        }
    }
}

/// Store assistant response in conversation history
pub fn store_response(db_path: &str, user_id: &str, channel: &str, content: &str) -> Result<(), rusqlite::Error> {
    let conn = rusqlite::Connection::open(db_path)?;
    conn.execute(
        "INSERT INTO conversations (user_id, channel, role, content)
         VALUES (?1, ?2, 'assistant', ?3)",
        [user_id, channel, content]
    )?;
    Ok(())
}
```

---

### Phase 11 Summary

| Task | Component | Purpose |
|------|-----------|---------|
| 22 | User Model | SQLite schema with user_id FK on all tables |
| 23 | Policy AllowList | Configure allowed users in policy.yaml |
| 24 | Message Listener | Watch WhatsApp/Email, store messages, wake agent |
| 25 | Context-Aware | Include user's conversation history in prompts |
| 26 | Response Sender | Send replies back via same channel |

**Privacy Guarantees:**
- All tables have `user_id` foreign key
- Queries always filter by `WHERE user_id = ?`
- Unknown senders are silently ignored (no response)
- Claude prompts only include that user's context
- Audit log tracks which user triggered each action


---

## Phase 11 (Revised): Owner-Controlled Agent Model

**Key Change**: One owner/controller (you) with full access. Agent acts as your delegate to contacts based on your instructions.

### Revised User Model

```yaml
# policy.yaml
owner:
  id: "sundar"
  phone: "+16468259551"
  email: "sundar@example.com"
  # Owner has full access to everything

# Contacts the agent can interact with (based on owner instructions)
contacts:
  - id: "ron"
    phone: "+1234567890"
    email: "ron@company.com"
    # Scope defined by owner instructions, not static config

  - id: "alice"  
    phone: "+0987654321"
    email: "alice@example.com"
```

### SQLite Schema (Revised)

```sql
-- Single owner (from policy)
CREATE TABLE owner (
    id TEXT PRIMARY KEY,
    phone TEXT,
    email TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Contacts the agent can interact with
CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    display_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT
);

-- Owner's instructions about each contact
-- "Discuss execwall with Ron but don't share any other info"
CREATE TABLE contact_scopes (
    id INTEGER PRIMARY KEY,
    contact_id TEXT NOT NULL REFERENCES contacts(id),
    instruction TEXT NOT NULL,           -- owner's instruction
    topics_allow TEXT,                   -- JSON array: ["execwall", "pricing"]
    topics_deny TEXT,                    -- JSON array: ["fund", "personal"]
    tools_allow TEXT,                    -- JSON array of tools contact can trigger
    expires_at TEXT,                     -- optional expiration
    created_at TEXT DEFAULT (datetime('now')),
    created_by TEXT DEFAULT 'owner'
);
CREATE INDEX idx_scopes_contact ON contact_scopes(contact_id);

-- Conversations (owner sees all, contacts see only theirs)
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    participant_id TEXT NOT NULL,        -- owner or contact id
    participant_type TEXT NOT NULL,      -- "owner" or "contact"
    channel TEXT NOT NULL,
    role TEXT NOT NULL,                  -- "user" or "assistant"
    content TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_convos_participant ON conversations(participant_id, created_at);

-- Owner's tasks (only owner can create/see)
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT,
    priority INTEGER DEFAULT 0,
    source TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);

-- Owner's notes
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    tags TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

-- Owner's reminders
CREATE TABLE reminders (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    notified_at TEXT
);

-- Pending approvals (owner approves)
CREATE TABLE pending_approvals (
    id INTEGER PRIMARY KEY,
    requested_by TEXT,                   -- contact who triggered or "agent"
    tool TEXT NOT NULL,
    args TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    decided_at TEXT,
    decision TEXT
);
```

### Owner Instructions Examples

Owner (via WhatsApp/CLI) says:
```
"Allow Ron to discuss execwall - features, pricing, installation. 
Don't share fund info or personal stuff."
```

Agent stores:
```json
{
  "contact_id": "ron",
  "instruction": "Allow Ron to discuss execwall - features, pricing, installation. Don't share fund info or personal stuff.",
  "topics_allow": ["execwall", "features", "pricing", "installation"],
  "topics_deny": ["fund", "personal", "calendar", "tasks"]
}
```

### Agent Behavior per Participant

```rust
fn handle_message(msg: &IncomingMessage, db: &str, policy: &str) {
    if is_owner(&msg.from) {
        // Owner: full access, can give instructions
        handle_owner_message(msg, db, policy);
    } else if let Some(contact) = get_contact(&msg.from) {
        // Known contact: respond within scope
        let scopes = get_contact_scopes(db, &contact.id);
        handle_contact_message(msg, &contact, &scopes, db, policy);
    } else {
        // Unknown: ignore silently
        log_unknown_sender(&msg.from);
    }
}

fn handle_owner_message(msg: &IncomingMessage, db: &str, policy: &str) {
    // Check if it's an instruction about a contact
    if let Some(instruction) = parse_contact_instruction(&msg.content) {
        // "Allow Ron to discuss X" or "Don't let Alice see Y"
        store_contact_scope(db, &instruction);
        respond("Got it. I'll handle Ron that way.");
        return;
    }
    
    // Otherwise, normal owner interaction (tasks, calendar, questions, etc.)
    let context = collect_full_context(db);  // Owner sees everything
    let decision = get_agent_decision(&context, policy);
    execute_and_respond(decision, msg);
}

fn handle_contact_message(msg: &IncomingMessage, contact: &Contact, scopes: &[Scope], db: &str, policy: &str) {
    // Build scoped context (only what owner allowed)
    let context = collect_scoped_context(db, contact, scopes);
    
    // Include scope instructions in system prompt
    let system_prompt = format!(r#"
You are AgentExW, acting on behalf of the owner.

Contact: {} 
Owner's instructions for this contact:
{}

IMPORTANT: 
- Only discuss topics the owner has allowed
- Do not reveal: {}
- If asked about restricted topics, politely decline
"#, 
        contact.display_name,
        scopes.iter().map(|s| &s.instruction).collect::<Vec<_>>().join("\n"),
        scopes.iter().flat_map(|s| &s.topics_deny).collect::<Vec<_>>().join(", ")
    );
    
    let decision = get_agent_decision_scoped(&context, &system_prompt, policy);
    execute_and_respond(decision, msg);
}
```

### Owner Commands (via WhatsApp/CLI)

| Command | Action |
|---------|--------|
| `"Add Ron +1234567890"` | Add contact |
| `"Let Ron discuss execwall only"` | Set scope |
| `"Block Ron from fund topics"` | Add deny |
| `"Show Ron's conversations"` | View contact history |
| `"What did Ron ask about?"` | Summary |
| `"Remove Ron"` | Delete contact |
| `"Who messaged today?"` | Activity summary |

### Privacy Guarantees (Revised)

1. **Owner sees everything**: All conversations, all data
2. **Contacts are scoped**: Only see what owner allows via instructions
3. **No cross-contact leakage**: Ron can't see Alice's conversations
4. **Topics are enforced**: Agent refuses to discuss denied topics
5. **Unknown senders ignored**: No response to strangers


---

### Email Handling (Same Model)

Email follows the same owner-controlled model:

```
Email from ron@company.com arrives
        ↓
Lookup contact by email → Found "ron"
        ↓
Lookup contact_scopes for "ron"
        ↓
Found: "Discuss execwall only"
        ↓
Generate response within scope
        ↓
Send reply via himalaya
```

### Owner Email Instructions

Owner can say (via WhatsApp/email/CLI):

```
"Add investor@fund.com as contact 'investor'"
"Investor can ask about fund performance and reports only"
"Don't share any technical details with investor"
```

Stored as:
```sql
INSERT INTO contacts (id, email, display_name) 
VALUES ('investor', 'investor@fund.com', 'Fund Investor');

INSERT INTO contact_scopes (contact_id, instruction, topics_allow, topics_deny)
VALUES ('investor', 
        'Can ask about fund performance and reports only',
        '["fund performance", "reports", "returns"]',
        '["technical", "code", "infrastructure", "personal"]');
```

### Email Response Flow

```rust
fn handle_email(email: &Email, db: &str, policy: &str) {
    let from_addr = extract_email_address(&email.from);
    
    // Check if from owner
    if is_owner_email(&from_addr) {
        handle_owner_email(email, db, policy);
        return;
    }
    
    // Lookup contact by email
    let contact = match get_contact_by_email(db, &from_addr) {
        Some(c) => c,
        None => {
            // Unknown sender - log and ignore
            log_unknown_email(&from_addr, &email.subject);
            return;
        }
    };
    
    // Get scopes for this contact
    let scopes = get_contact_scopes(db, &contact.id);
    if scopes.is_empty() {
        // Contact exists but no scope defined - ask owner
        notify_owner(&format!(
            "Email from {} ({}). No instructions set. Reply with scope or 'ignore'.",
            contact.display_name, from_addr
        ));
        return;
    }
    
    // Store incoming email in conversations
    store_conversation(db, &contact.id, "contact", "email", "user", &format!(
        "Subject: {}\n\n{}", email.subject, email.body
    ));
    
    // Generate scoped response
    let response = generate_scoped_response(email, &contact, &scopes, db, policy);
    
    // Send reply via himalaya (through execwall)
    send_email_reply(email, &response, policy);
    
    // Store response
    store_conversation(db, &contact.id, "contact", "email", "assistant", &response);
}

fn send_email_reply(original: &Email, response: &str, policy: &str) {
    // Build reply via execwall
    let output = std::process::Command::new("execwall")
        .args(&["--policy", policy, "-c", "email_reply"])
        .env("EMAIL_TO", &original.from)
        .env("EMAIL_SUBJECT", &format!("Re: {}", original.subject))
        .env("EMAIL_IN_REPLY_TO", &original.message_id)
        .env("EMAIL_BODY", response)
        .output();
    
    match output {
        Ok(o) if o.status.success() => {
            log(&format!("Replied to {}", original.from));
        }
        _ => {
            log(&format!("Failed to reply to {}", original.from));
        }
    }
}
```

### Email Tool (via execwall)

```python
#!/usr/bin/env python3
# /usr/lib/execwall/tools/email_reply.py
"""Send email reply via himalaya"""

import os
import subprocess
import json

def main():
    to = os.environ.get('EMAIL_TO')
    subject = os.environ.get('EMAIL_SUBJECT', '')
    in_reply_to = os.environ.get('EMAIL_IN_REPLY_TO', '')
    body = os.environ.get('EMAIL_BODY', '')
    
    if not to or not body:
        print(json.dumps({"error": "Missing EMAIL_TO or EMAIL_BODY"}))
        return 1
    
    # Build MML message for himalaya
    mml = f"""From: AgentExW <sentra@lma.llc>
To: {to}
Subject: {subject}
In-Reply-To: {in_reply_to}

{body}
"""
    
    # Send via himalaya
    result = subprocess.run(
        ['himalaya', 'message', 'send'],
        input=mml,
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(json.dumps({"success": True, "to": to}))
        return 0
    else:
        print(json.dumps({"error": result.stderr}))
        return 1

if __name__ == '__main__':
    exit(main())
```

### Summary: Unified Contact Model

| Channel | Lookup Key | Same Scope Rules | Response Via |
|---------|-----------|------------------|--------------|
| WhatsApp | phone number | ✓ | OpenClaw WA bridge |
| Email | email address | ✓ | himalaya SMTP |

**One contact can have both phone and email:**
```sql
INSERT INTO contacts (id, phone, email, display_name)
VALUES ('ron', '+1234567890', 'ron@company.com', 'Ron');
```

**Same scope applies to both channels:**
```sql
INSERT INTO contact_scopes (contact_id, instruction, topics_allow)
VALUES ('ron', 'Discuss execwall only', '["execwall"]');
```

When Ron messages via WhatsApp OR email, same rules apply.


---

### Task 27: Fund Scripts Directory (Read-Only Execution)

**Concept**: You maintain a directory of trusted Python scripts for fund operations. Agent can run them but cannot modify.

```
/var/lib/execwall/fund-scripts/     (owner: root, mode: 755)
├── check_positions.py              (mode: 644, read-only)
├── monitor_pnl.py
├── scan_logs.py
├── alert_thresholds.py
├── generate_report.py
└── README.md                       (documents each script)
```

**Security Model:**

| Actor | Read | Write | Execute |
|-------|------|-------|---------|
| Owner (you) | ✓ | ✓ | ✓ |
| AgentExW | ✓ | ✗ | ✓ (via python_runner) |
| Contacts | ✗ | ✗ | ✗ |

### Policy Configuration

```yaml
# policy.yaml

profiles:
  # Fund scripts profile - read-only execution
  fund_scripts:
    description: "Execute pre-approved fund monitoring scripts"
    syscall_profile: python_sandbox
    filesystem:
      read_allow:
        - "/var/lib/execwall/fund-scripts"    # Scripts directory
        - "/var/log/fund"                      # Fund logs to analyze
        - "/var/lib/execwall/fund-data"        # Data files
        - "/usr/lib/python3"                   # Python stdlib
        - "/usr/local/lib/python3"             # Site packages
      write_allow:
        - "/tmp/fund-output"                   # Temp output only
      write_deny:
        - "/var/lib/execwall/fund-scripts"    # Cannot modify scripts!
    network:
      allow: false                             # No network access
    limits:
      timeout_sec: 300                         # 5 min max
      mem_max_mb: 1024
      pids_max: 32
    env_inject:
      FUND_SCRIPTS_DIR: "/var/lib/execwall/fund-scripts"
      FUND_LOGS_DIR: "/var/log/fund"
      PYTHONPATH: "/var/lib/execwall/fund-scripts"

# Tool definition for running fund scripts
tools:
  fund_run:
    path: "/usr/lib/execwall/tools/fund_run.py"
    profile: fund_scripts
    description: "Run a fund monitoring script"
    args_schema:
      script:
        type: string
        description: "Script name (e.g., 'check_positions.py')"
        pattern: "^[a-zA-Z0-9_]+\\.py$"   # Only .py files, no paths
      args:
        type: array
        description: "Arguments to pass to script"
        optional: true
```

### Fund Script Runner Tool

```python
#!/usr/bin/env python3
# /usr/lib/execwall/tools/fund_run.py
"""
Run a fund monitoring script from the approved directory.
Scripts are read-only - agent cannot modify them.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(os.environ.get('FUND_SCRIPTS_DIR', '/var/lib/execwall/fund-scripts'))
OUTPUT_DIR = Path('/tmp/fund-output')

def main():
    # Parse input
    try:
        request = json.loads(os.environ.get('ARGS', '{}'))
    except json.JSONDecodeError:
        request = {}
    
    script_name = request.get('script') or os.environ.get('FUND_SCRIPT')
    script_args = request.get('args', [])
    
    if not script_name:
        print(json.dumps({"error": "No script specified"}))
        return 1
    
    # Security: only allow simple filenames, no path traversal
    if '/' in script_name or '..' in script_name:
        print(json.dumps({"error": "Invalid script name"}))
        return 1
    
    # Must end in .py
    if not script_name.endswith('.py'):
        script_name += '.py'
    
    script_path = SCRIPTS_DIR / script_name
    
    # Check script exists and is readable
    if not script_path.exists():
        available = [f.name for f in SCRIPTS_DIR.glob('*.py')]
        print(json.dumps({
            "error": f"Script '{script_name}' not found",
            "available_scripts": available
        }))
        return 1
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Run the script
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)] + script_args,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout
            cwd=str(SCRIPTS_DIR),
            env={
                **os.environ,
                'FUND_OUTPUT_DIR': str(OUTPUT_DIR),
            }
        )
        
        output = {
            "script": script_name,
            "exit_code": result.returncode,
            "stdout": result.stdout[:50000],  # Limit output size
            "stderr": result.stderr[:10000],
        }
        
        # Check for output files
        output_files = list(OUTPUT_DIR.glob('*'))
        if output_files:
            output["output_files"] = [f.name for f in output_files]
        
        print(json.dumps(output))
        return result.returncode
        
    except subprocess.TimeoutExpired:
        print(json.dumps({"error": "Script timed out (5 min limit)"}))
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1

if __name__ == '__main__':
    sys.exit(main())
```

### Example Fund Scripts

```python
# /var/lib/execwall/fund-scripts/check_positions.py
"""Check current positions from IBKR logs"""
import json
import os
from pathlib import Path

LOGS_DIR = Path(os.environ.get('FUND_LOGS_DIR', '/var/log/fund'))

def main():
    positions_file = LOGS_DIR / 'positions.json'
    if not positions_file.exists():
        print(json.dumps({"error": "No positions file found"}))
        return
    
    positions = json.loads(positions_file.read_text())
    
    summary = {
        "total_positions": len(positions),
        "positions": [
            {"symbol": p["symbol"], "qty": p["qty"], "pnl": p.get("unrealizedPnL", 0)}
            for p in positions[:20]  # Top 20
        ],
        "total_unrealized_pnl": sum(p.get("unrealizedPnL", 0) for p in positions)
    }
    
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
```

```python
# /var/lib/execwall/fund-scripts/scan_logs.py
"""Scan fund logs for errors or anomalies"""
import json
import os
import re
from pathlib import Path
from datetime import datetime, timedelta

LOGS_DIR = Path(os.environ.get('FUND_LOGS_DIR', '/var/log/fund'))

def main():
    # Look at last 24 hours of logs
    cutoff = datetime.now() - timedelta(hours=24)
    
    errors = []
    warnings = []
    
    for log_file in LOGS_DIR.glob('*.log'):
        try:
            for line in log_file.read_text().splitlines()[-1000:]:  # Last 1000 lines
                if 'ERROR' in line:
                    errors.append({"file": log_file.name, "line": line[:200]})
                elif 'WARNING' in line or 'WARN' in line:
                    warnings.append({"file": log_file.name, "line": line[:200]})
        except Exception as e:
            pass
    
    result = {
        "scanned_files": len(list(LOGS_DIR.glob('*.log'))),
        "errors_found": len(errors),
        "warnings_found": len(warnings),
        "recent_errors": errors[:10],
        "recent_warnings": warnings[:10]
    }
    
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
```

```python
# /var/lib/execwall/fund-scripts/monitor_pnl.py
"""Monitor P&L and alert on thresholds"""
import json
import os
from pathlib import Path

LOGS_DIR = Path(os.environ.get('FUND_LOGS_DIR', '/var/log/fund'))
OUTPUT_DIR = Path(os.environ.get('FUND_OUTPUT_DIR', '/tmp/fund-output'))

# Thresholds
DAILY_LOSS_ALERT = -10000  # Alert if daily loss exceeds $10k
POSITION_LOSS_ALERT = -5000  # Alert if single position loss exceeds $5k

def main():
    pnl_file = LOGS_DIR / 'daily_pnl.json'
    if not pnl_file.exists():
        print(json.dumps({"error": "No P&L file found"}))
        return
    
    pnl_data = json.loads(pnl_file.read_text())
    
    alerts = []
    
    # Check daily P&L
    daily_pnl = pnl_data.get('daily_pnl', 0)
    if daily_pnl < DAILY_LOSS_ALERT:
        alerts.append({
            "type": "DAILY_LOSS",
            "severity": "HIGH",
            "message": f"Daily P&L is ${daily_pnl:,.2f} (threshold: ${DAILY_LOSS_ALERT:,.2f})"
        })
    
    # Check position-level P&L
    for position in pnl_data.get('positions', []):
        pos_pnl = position.get('unrealizedPnL', 0)
        if pos_pnl < POSITION_LOSS_ALERT:
            alerts.append({
                "type": "POSITION_LOSS",
                "severity": "MEDIUM",
                "symbol": position['symbol'],
                "message": f"{position['symbol']} P&L is ${pos_pnl:,.2f}"
            })
    
    result = {
        "daily_pnl": daily_pnl,
        "alerts": alerts,
        "alert_count": len(alerts),
        "status": "ALERT" if alerts else "OK"
    }
    
    # Write alert file if any alerts (triggers agent wake)
    if alerts:
        alert_file = OUTPUT_DIR / 'pnl_alerts.json'
        alert_file.write_text(json.dumps(alerts))
    
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
```

### Agent Usage

Owner can say:
- `"Check positions"` → runs `check_positions.py`
- `"Scan fund logs for errors"` → runs `scan_logs.py`
- `"Monitor P&L"` → runs `monitor_pnl.py`
- `"Run check_positions with --detailed"` → passes args

Agent maps these to `fund_run` tool:
```json
{
  "tool": "fund_run",
  "args": {
    "script": "check_positions.py",
    "args": ["--detailed"]
  }
}
```

### Directory Setup

```bash
# Create fund scripts directory (owner only can write)
sudo mkdir -p /var/lib/execwall/fund-scripts
sudo mkdir -p /var/lib/execwall/fund-data
sudo mkdir -p /var/log/fund
sudo mkdir -p /tmp/fund-output

# Set permissions - only root/owner can modify scripts
sudo chown root:root /var/lib/execwall/fund-scripts
sudo chmod 755 /var/lib/execwall/fund-scripts

# Scripts are read-only
sudo chmod 644 /var/lib/execwall/fund-scripts/*.py

# Agent can write to output dir only
sudo chown execwall:execwall /tmp/fund-output
sudo chmod 750 /tmp/fund-output

# Agent can read logs
sudo chown root:execwall /var/log/fund
sudo chmod 750 /var/log/fund
```

### Security Summary

| What | Allowed | Enforced By |
|------|---------|-------------|
| Run scripts from `/var/lib/execwall/fund-scripts/` | ✓ | Policy profile |
| Read fund logs | ✓ | Filesystem allow |
| Modify scripts | ✗ | Unix permissions + policy |
| Run arbitrary Python | ✗ | Only named scripts |
| Network access | ✗ | Profile denies network |
| Access other dirs | ✗ | Filesystem deny-by-default |

