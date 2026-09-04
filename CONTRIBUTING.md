# Contributing to AynOps

Thank you for your interest in contributing to **AynOps**! AynOps is an open-source, high-performance Model Context Protocol (MCP) server engineered to provide deterministic cybersecurity reconnaissance, attack surface mapping, and OSINT telemetry directly to AI agents.

We welcome contributions from cybersecurity researchers, software engineers, and open-source enthusiasts. Whether you are implementing a new reconnaissance tool, enhancing our multi-wave signal extraction engine, fixing a bug, or refining documentation, your effort is greatly appreciated.

---

## 📚 Table of Contents

- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Adding a New Standalone Tool](#adding-a-new-standalone-tool)
- [Adding a Tool to Full Recon (Multi-Wave Pipeline)](#adding-a-tool-to-full-recon-multi-wave-pipeline)
- [Manual Testing](#manual-testing)
- [Commit & PR Guidelines](#commit--pr-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Reporting Security Issues](#reporting-security-issues)

---

## 📌 Before You Start

Before authoring code or submitting pull requests, please review our foundational development principles:

1. **Non-Destructive & Safe Operations**: AynOps is strictly a reconnaissance and security assessment server. All tools must perform non-destructive, read-only telemetry gathering and analysis. Exploit payloads, denial-of-service triggers, or unauthorized modification mechanics are strictly prohibited.
2. **Authorized Use Only**: Scan only systems that you own or have explicit permission to test. Do not use AynOps to perform reconnaissance or security assessments against systems without authorization. For responsible-use requirements, see [SECURITY.md](SECURITY.md). For a safe, intentionally vulnerable target, use [scanme.nmap.org](https://scanme.nmap.org/).
3. **Legal & Responsible Use**: Security assessment capabilities must be used only for legitimate, authorized security testing and in accordance with applicable laws and regulations.
4. **Local-First & Zero-Telemetry Egress**: AynOps operates locally over standard I/O (`stdio`). Tool implementations must never transmit telemetry, target domains, IP addresses, or environment credentials to unauthorized third-party telemetry aggregators.
5. **Fail-Safe Server Resilience**: An MCP server process must **never crash**. Network timeouts, socket failures, and malformed upstream responses must be caught gracefully and returned as structured error payloads (`{"success": False, "error": "..."}`).
6. **Community Discussion**: For major refactors, architectural shifts, or complex new tool integrations, please open a thread in [GitHub Discussions](https://github.com/AynOps/AynOps/discussions) or create an RFC issue first to align with maintainers.

---

## 💻 Development Setup

### 1. Prerequisites

Ensure your development environment has the following tools installed:

- **Python**: `>= 3.12` ([Download Python](https://www.python.org/downloads/))
- **Astral `uv`**: Recommended package and virtual environment manager ([Install uv](https://docs.astral.sh/uv/getting-started/installation))
- **Nmap**: Network mapper binary available on your system `PATH` ([Download Nmap](https://nmap.org/download.html))
- **Git**: Distributed version control system ([Download Git](https://git-scm.com/))
- **Docker** *(Optional)*: For containerized testing ([Download Docker](https://www.docker.com/))

---

### 2. Local Environment Provisioning

Clone the repository and bootstrap an isolated virtual environment:

```bash
# Clone the repository
git clone https://github.com/AynOps/AynOps.git
cd AynOps

# Provision virtual environment and install all dependencies via uv (Recommended)
uv sync
```

*Alternatively, using standard Python `venv`:*

```bash
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install project and dev dependencies
pip install -e .
pip install pytest==9.0.3
```

---

### 3. Verify System Dependencies (Nmap)

Nmap must be accessible in your system `PATH` for the port scanning engine:

```bash
nmap --version
```

- **macOS**: `brew install nmap`
- **Debian / Ubuntu / Kali**: `sudo apt update && sudo apt install -y nmap`
- **Fedora / RHEL**: `sudo dnf install -y nmap`
- **Arch Linux**: `sudo pacman -S nmap`
- **Windows**: Run the Nmap installer and add `C:\Program Files (x86)\Nmap` (or `C:\Program Files\Nmap`) to your system `PATH` environment variables.

---

### 4. Configure Environment Variables

Copy `.env.example` to create your local `.env` file:

```bash
# On Linux/macOS:
cp .env.example .env

# On Windows (PowerShell):
Copy-Item .env.example .env
```

| Variable | Required | Description | Source |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | Optional | Needed for `ip_reputation` | [abuseipdb.com](https://www.abuseipdb.com) |
| `HIBP_API_KEY` | Optional | Needed for `hibp_check` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |

> [!WARNING]
> Never commit `.env` files, API keys, or active credentials to Git. Ensure `.env` remains in `.gitignore`.

---

### 5. Run the Automated Test Suite

Execute the test suite to confirm your local environment is pristine:

```bash
# Using uv
uv run pytest

# Using active virtualenv
pytest -v
```

All tests should pass cleanly without errors.

---

## 🗂️ Project Structure

AynOps maintains a modular directory layout separating core tool implementations, multi-wave signal extraction, technology fingerprinting, protocol manifests, and test suites:

```
AynOps/
├── .github/                  # GitHub workflows, templates, and assets
│   ├── images/               # Documentation and demo media
│   ├── ISSUE_TEMPLATE/       # Issue templates
│   └── workflows/            # CI/CD workflows
├── docs/                     # Extended documentation
│   └── tools/                # Per-tool documentation
├── tests/                    # Unit and integration tests
├── tools/                    # MCP reconnaissance tools
│   ├── fingerprint/          # Web technology fingerprinting engine
│   ├── prompts/              # MCP prompt templates
│   └── signals/              # Signal extraction framework
├── utils/                    # Shared utilities and helpers
├── .env.example              # Environment variable template
├── .gitignore                # Git ignored files and directories
├── .python-version           # Pins Python 3.12
├── CONTRIBUTING.md           # Contribution guidelines
├── Dockerfile                # Container configuration
├── glama.json                # Glama MCP configuration
├── LICENSE                   # MIT License
├── mcp.json                  # MCP metadata and tool manifests
├── pyproject.toml            # Project metadata and dependencies
├── README.md                 # Project documentation
├── SECURITY.md               # Security policy
├── server.json               # MCP server package schema
├── server.py                 # FastMCP server entrypoint
└── uv.lock                   # Dependency lockfile
```

---

## 🛠️ Making Changes

### 1. Branching Strategy

Always create a dedicated feature or fix branch from `main`:

```bash
# For a new reconnaissance tool
git checkout -b feat/shodan-lookup

# For a bugfix
git checkout -b fix/dns-srv-timeout

# For documentation updates
git checkout -b docs/contributing-guide
```

---

### 2. Core Implementation Standards

When modifying or adding Python code in AynOps:

1. **Input Normalization & Validation**:
   - Always sanitize domain inputs using `utils.helpers.normalize_domain()` and `utils.helpers.is_valid_domain()`.
   - Validate IP addresses using Python's standard `ipaddress` library (`ipaddress.ip_address()`).
2. **Explicit Network Timeouts**:
   - Never initiate unbounded network sockets, HTTP requests, or subprocess calls. Always enforce sensible timeouts (e.g. `timeout=10` for HTTP, `timeout=5` for DNS/WHOIS sockets).
3. **Structured Response Contracts**:
   - Every tool function must return a standard dictionary payload containing `"success": True` or `"success": False`.
   - Error responses must follow the format: `{"success": False, "error": "<detailed message>"}`.
4. **Graceful Degradation**:
   - If an optional data element cannot be resolved (e.g., missing WHOIS field or unresolvable DNS record), omit or set the key to `None` rather than failing the entire tool call.

---

## ➕ Adding a New Standalone Tool

To author and register a new standalone MCP reconnaissance tool:

### Step 1: Create the Tool Module

Create a new file in `tools/` (e.g., `tools/my_tool.py`):

```python
"""
tools/my_tool.py

Module implementation for my_tool.
"""

from utils.helpers import is_valid_domain, normalize_domain

def my_tool(domain: str) -> dict:
    """
    Perform a specialized security audit on the specified domain.

    Args:
        domain (str): Target domain name to evaluate.

    Returns:
        dict: Structured assessment findings with 'success' boolean status.
    """
    try:
        domain = normalize_domain(domain)
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format provided."}

        # Perform deterministic reconnaissance / inspection
        findings = {
            "target": domain,
            "inspected_endpoints": ["api", "admin"],
            "status": "secure"
        }

        return {
            "success": True,
            "domain": domain,
            "data": findings
        }

    except Exception as e:
        return {"success": False, "error": f"Execution failed: {str(e)}"}
```

*For tools operating on IP addresses:*

```python
import ipaddress

def my_ip_tool(ip_address: str) -> dict:
    try:
        ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        return {"success": False, "error": "Invalid IPv4/IPv6 address format."}

    # Proceed with execution
    ...
```

---

### Step 2: Register Tool in FastMCP Server Entrypoint

Register the function in `server.py`:

```python
from tools.my_tool import my_tool

# Register tool on FastMCP instance
mcp.tool()(my_tool)
```

---

### Step 3: Author Unit Tests

Create a corresponding test suite in `tests/test_my_tool.py`:

```python
from tools.my_tool import my_tool

def test_my_tool_success():
    # Test valid input path
    result = my_tool("example.com")
    assert result["success"] is True
    assert result["domain"] == "example.com"

def test_my_tool_invalid_domain():
    # Test failure path for invalid domain
    result = my_tool("invalid_domain..com")
    assert result["success"] is False
    assert "Invalid domain format" in result["error"]
```

Run your new test suite:

```bash
uv run pytest tests/test_my_tool.py -v
```

---

### Step 4: Update Manifests & Documentation

Ensure the tool is documented and registered across all project metadata files:

1. **`README.md`**: Add the tool entry to the **Standalone Offensive Tools** table.
2. **`mcp.json`**: Add the tool definition to the `"tools"` array:
   ```json
   {
     "name": "my_tool",
     "description": "One-line description of the security inspection performed.",
     "input": {
       "domain": "string"
     }
   }
   ```

For tools that require an external system dependency, set `"requires_system_dependency"` to the dependency name (for example, `"nmap"`). For API-dependent tools, set `"requires_api_key"` to `true` and provide the corresponding `"api_key_env"` and `"api_key_url"` values. Optional fields should be omitted when they are not applicable rather than set to `false` or `null`.


3. **`server.json`**: If your tool requires environment variables, define them under the `"environmentVariables"` array in `"packages"`. Each variable should specify its `"name"`, `"description"` `"isRequired"`, `"isSecret"`, and `"format"` fields.
4. **`.env.example`**: Add placeholder entries for new API keys (if applicable).
5. **`pyproject.toml` / `uv.lock`**: Add new third-party packages only if strictly necessary (`uv add <package>`).

---

## ⚡ Adding a Tool to Full Recon (Multi-Wave Pipeline)

When adding a tool that contributes core telemetry to the automated `full_recon` pipeline, follow these additional integration steps:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 Wave Execution Engine                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Wave 1: Lightweight base DNS, WHOIS, SSL, ASN, and email anti-spoofing queries         │
│ Wave 2: Aggressive Nmap port scanning, web tech fingerprinting, headers, crt.sh logs   │
│ Wave 3: Conditional threat intelligence (e.g. AbuseIPDB) requiring resolved target IP  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Register in `tools/signals/registry.py`

Bind the tool function, execution wave, argument resolver, and signal extractor in `TOOL_REGISTRY`:

```python
from tools.my_tool import my_tool
from tools.signals.my_tool import my_tool_extractor

TOOL_REGISTRY = [
    # ... existing wave tools ...
    {
        "name": "my_tool",
        "fn": my_tool,
        "wave": 1,  # 1 = Base Recon, 2 = Heavy Scans, 3 = Dynamic Threat Feeds
        "args": lambda domain, results: (domain,),
        "extractor": my_tool_extractor,
    },
]
```

*If the tool depends on another tool's output (e.g. resolved IP address), define `should_run` and `skip_reason`:*

```python
{
    "name": "my_ip_tool",
    "fn": my_ip_tool,
    "wave": 3,
    "args": lambda domain, results: (extract_ip(results),),
    "should_run": lambda domain, results: extract_ip(results) is not None,
    "skip_reason": "No IP resolved from Wave 1/2 — tool execution skipped",
    "extractor": my_ip_tool_extractor,
}
```

---

### Step 2: Implement Signal Extractor in `tools/signals/`

Create `tools/signals/my_tool.py` to extract actionable telemetry from the raw tool response:

> **Note:** The shared `signals` dictionary, including `auto_warnings`, is pre-initialized by `extract_signals()` before the extractor is called.

```python
def my_tool_extractor(result: dict, signals: dict) -> None:
    """
    Extract normalized signals and evaluate risk thresholds.
    """
    if not result.get("success"):
        return

    data = result.get("data", {})
    signals["my_signal_metric"] = data.get("metric_value")

    # Evaluate heuristic risk thresholds and append to auto_warnings
    if data.get("is_vulnerable"):
        signals["auto_warnings"].append(
            f"Target {result.get('domain')} exhibits critical exposure in my_tool check"
        )
```

> **Note:** In `should_run` callbacks, `results` contains the raw results of tools executed in **previous waves**, keyed by their registry `name`. Use `results.get("tool_name")` to safely access a tool's output when deciding whether the current tool should run. For example, `results.get("whois")` returns the raw WHOIS result, or `None` if the tool has not produced a result.

---

### Step 3: Register Default Signal Keys

In `tools/signals/extractor.py`, add your signal key to the default `signals` dictionary to guarantee schema integrity:

* Scalar values: `None` — e.g. `domain_expiry_days`, `ssl_days_remaining`, `asn_number`, `asn_org`, `asn_ip`, `asn_country`
* Lists / collections: `[]` — e.g. `dns_missing_records`, `open_ports`, `software_detected`, `missing_security_headers`, `auto_warnings`
* Sub-dictionaries: `{}` — e.g. `email_security`
* Counters: `0` — e.g. `ip_abuse_score`, `subdomain_count`
* Booleans: `False` — e.g. `ip_reputation_flagged`

Keep the default value consistent with the type of data the extractor will store.

---

### Step 4: Update Telemetry Report Formatter

In `tools/fullrecon_tool.py`, update `_format_signals_block()` to ensure the downstream LLM receives your extracted signal in the final structured synthesis.

Add the new signal to the appropriate section of `_format_signals_block()` and preserve the existing formatting conventions.

For nested signals, include the relevant fields expected by the formatter:

* `email_security`: `security_score`, `rating`, `spf_found`, `spf_policy`, `dkim_found`, `dmarc_found`, `dmarc_policy`
* `cves_found`: list of CVE objects containing `id`, `cvss`, and `summary`

Use safe defaults when optional signal data is unavailable, consistent with the existing implementation.

---

### Step 5: Test Signal Extractor

Add unit tests in `tests/test_signals_extractors.py` asserting that mocked raw tool outputs correctly populate the `signals` dictionary and trigger expected warnings.

---

## 🧪 Manual Testing

Before opening a pull request, perform manual verification of your changes:

### 1. Interactive Testing with FastMCP Inspector

FastMCP ships with an interactive browser-based MCP inspector to inspect tool schemas and test tool invocations:

```bash
# Launch FastMCP Inspector
uv run fastmcp dev inspector server.py
```

Verify that:
- The tool appears in the listed capabilities.
- JSON-RPC parameter schemas render accurately.
- Invocations return expected JSON payloads.
- Invalid parameter submissions fail with structured error responses.

---

### 2. Docker Stdio Verification

If you modified dependencies, `Dockerfile`, or server startup scripts, smoke-test the container:

```bash
# Build local container
docker build -t aynops:test .
```

After building the image, verify that the container starts successfully and initializes the MCP server in stdio mode:

```bash
# Validate stdio MCP listener initialization
docker run --rm -i aynops:test
# Press Ctrl+C to terminate
```

This is a basic container smoke test and does not require API keys. It verifies that the Docker image can start the MCP server successfully.


> **Note:** API keys are only required when testing tools that depend on external services such as AbuseIPDB or Have I Been Pwned. These credentials should be supplied at runtime rather than included in the Docker image.

For API-dependent testing, credentials can be provided using a `.env` file. When using Docker's `--env-file`, use unquoted values to avoid quote characters being passed literally.

```bash
docker run --rm -i --env-file .env aynops:test
```

or as runtime environment variables:

```bash
docker run --rm -i \
  -e ABUSEIPDB_API_KEY="$ABUSEIPDB_API_KEY" \
  -e HIBP_API_KEY="$HIBP_API_KEY" \
  aynops:test
```


---

## 📝 Commit & PR Guidelines

### 1. Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat(tool): add whois domain expiry warning extractor`
- `fix(dns): prevent unhandled timeout on SRV queries`
- `perf(recon): optimize wave 2 async concurrency`
- `docs(readme): update Claude Desktop configuration path`
- `test(signals): add test coverage for SSL cert extractor`
- `refactor(helpers): streamline domain regex validation`

---

### 2. Submitting a Pull Request

1. Push your branch to your forked repository:
   ```bash
   git push origin feat/my-new-tool
   ```
2. Navigate to the AynOps GitHub repository and click **Compare & pull request**.
3. Complete the pull request template (`.github/PULL_REQUEST_TEMPLATE.md`):
   - **Closes**: Reference any related issue (e.g., `Closes #42`).
   - **Summary**: 1–2 sentences explaining the purpose of the change.
   - **What changed**: Detailed bullet points of code modifications.
   - **Verification**: Evidence of testing, test commands run, and pass status.

---

### 3. PR Review Checklist

Before requesting review, ensure your PR passes all items:

- [ ] Tool adheres to the standard pattern in `tools/`
- [ ] Inputs are validated via `utils.helpers` or standard `ipaddress`
- [ ] Returns structured `{"success": True/False, ...}` on all code execution paths
- [ ] Exceptions are caught cleanly — the MCP server process never crashes
- [ ] Comprehensive unit tests added in `tests/` with all tests passing (`uv run pytest`)
- [ ] Dependencies are kept minimal (no unnecessary heavy libraries)
- [ ] Tool table updated in `README.md`
- [ ] `mcp.json` updated with tool schema and parameter definitions
- [ ] `server.json` updated if environment variables were introduced
- [ ] `.env.example` updated with placeholder credentials (if applicable)
- [ ] No secrets, live API keys, or temporary debugging logs committed

---

## 🐛 Reporting Bugs

If you encounter unexpected behavior, unhandled exceptions, or schema mismatches:

1. Search existing [GitHub Issues](https://github.com/AynOps/AynOps/issues) to ensure the bug has not already been reported.
2. Open a new issue using our [Bug Report Template](https://github.com/AynOps/AynOps/issues/new?template=bug_report.yml).
3. Include your operating system, Python version, Nmap version, MCP client environment, full error stack trace, and reproduction steps.

---

## 🛡️ Reporting Security Issues

For vulnerabilities that could compromise user hosts, expose credentials, or enable arbitrary code execution:

- **Do NOT create public GitHub issues for critical security vulnerabilities.**
- Follow our responsible disclosure guidelines detailed in [SECURITY.md](SECURITY.md).
- Report privately via [GitHub Private Vulnerability Reporting](https://github.com/AynOps/AynOps/security/advisories/new) or email `gaoharimran29@gmail.com`.

---

<div align="center">
  <sub>Thank you for helping build and secure AynOps! </sub>
</div>
