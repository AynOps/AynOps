# Contributing to AynOps

Thanks for your interest in contributing! This project is actively growing and new tools are welcome. Every contribution — whether a new tool, bug fix, or documentation improvement — is appreciated.

---

## How to Add a New Tool

### 1. Create a New Tool

Add a new file inside the `tools/` directory:

```
tools/
└── my_tool.py
```

Implement your tool using the standard pattern:

```python
from utils.helpers import is_valid_domain

def your_tool_name(domain: str) -> dict:
    """
    One clear sentence describing what this tool does.
    """
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        result = {}

        return {
            "success": True,
            "domain": domain,
            # additional fields
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
```

For tools that operate on IP addresses, validate using Python's built-in `ipaddress` module:

```python
import ipaddress

try:
    ip = str(ipaddress.ip_address(ip_address.strip()))
except ValueError:
    return {"success": False, "error": "Invalid IP address format"}
```

---

### 2. Register the Tool

Import and register the tool in `server.py`:

```python
from tools.file_name import tool_name

mcp.tool()(tool_name)
```

---

### 3. Add Tests

Create a corresponding test file inside the `tests/` directory:

```
tests/
└── test_my_tool.py
```

Run the tests:

```bash
pytest tests/test_my_tool.py -v
```
All tests should pass without any warning or error.

Every new tool must include at least:

- One **happy-path** test (valid input, expected output)
- One **failure-path** test (invalid input or error handling)

---

### 4. Verify with MCP Inspector

Test the tool using MCP Inspector:

```bash
fastmcp dev inspector server.py
```

Verify that:

- The tool appears in the available tools list
- Inputs are validated correctly
- Expected results are returned
- Error handling works as intended

---

### 5. Update Documentation & `mcp.json`

- Add the tool to the tools table in `README.md`
- Add the relevant info in `mcp.json`
- If the tool requires an API key, document how to obtain and configure it in the README & mcp.json

---

### 6. Update `.env.example` and `requirements.txt` (If Applicable)

If your tool requires new environment variables, add them to `.env.example` with placeholder values:

```env
SHODAN_API_KEY=your_api_key_here
VIRUSTOTAL_API_KEY=your_api_key_here
```

> **Never** commit real API keys, secrets, or credentials to the repository.

---

## Adding a New Tool to Full Recon

Additional steps on top of [How to Add a New Tool](#how-to-add-a-new-tool), do those first.

### 1. Register the Tool

Add an entry to `TOOL_REGISTRY` in `tools/signals/registry.py`:

```python
from tools.your_tool_file import your_tool_name
from tools.signals.your_tool_file import your_tool_extractor

TOOL_REGISTRY = [
    ...
    {
        "name": "your_tool",
        "fn": your_tool_name,
        "wave": 1,
        "args": lambda domain, results: (domain,),
        "extractor": your_tool_extractor,
    },
]
```

- `wave`: 1 if the tool only needs `domain`. Use 2/3 if it needs `results` from an earlier wave, see `ip_reputation` for the pattern.
- `should_run` / `skip_reason`: optional, for tools that depend on another tool's output (see `ip_reputation`).

---

### 2. Write the Extractor

Add a file in `tools/signals/`:

```python
def your_tool_extractor(result, signals):
    if not result.get("success"):
        return

    signals["your_signal_key"] = result.get("some_field")
```

Add `your_signal_key` with a default value to the base `signals` dict in `tools/signals/extractor.py`, otherwise `_format_signals_block()` will `KeyError` on skipped/failed runs.

---

### 3. Add Auto-Warnings

Append plain-English strings to `signals["auto_warnings"]` when a value crosses a risk threshold. Follow the tiered pattern in `ssl_extractor`:

```python
if expiry < 0:
    signals["auto_warnings"].append(f"SSL certificate expired {abs(expiry)} days ago — all HTTPS traffic at risk")
elif expiry < 14:
    signals["auto_warnings"].append(f"SSL certificate expires in {expiry} days — CRITICAL, renew immediately")
```

---

### 4. Update the Report

- Add a line for your signal in `_format_signals_block()` in `tools/fullrecon_tool.py`; required, or the LLM never sees it.
- Update `tools/prompts/threat_analysis.py` only if the signal needs its own correlation rule (see "EVIDENCE QUALITY RULES").

---

### 5. Update Documentation

- Add the tool to `Included in full_recon` in `README.md`, not `Standalone Tools`.

---

### 6. Add Tests

- Unit test the tool (happy path + failure path).
- Test the extractor directly with mocked `result` dicts, asserting on `signals`.
- Update `mock_signals_full` in `tests/test_full_recon.py` if you added a new signal key.

```bash
pytest tests/ -v
```

---

## Steps to Contribute

1. Fork the repo
2. Create a branch:
   ```bash
   git checkout -b tool/your-tool-name
   ```
3. Add your tool to `tools/` following the pattern above
4. Test it in the MCP Inspector:
   ```bash
   fastmcp dev inspector server.py
   ```
5. Add unit test for tool in `tests/`.
6. Update the tools table in `README.md`
7. Update the relevant info in `mcp.json`
8. Update `requirements.txt` if you added a new dependency
9. Update `.env.example` if your tool needs an API key
10. Open a pull request with a short description

---

## PR Checklist

- [ ] Tool follows the existing pattern in `tools/`
- [ ] Input is validated (`is_valid_domain()` or `ipaddress` module)
- [ ] Returns `{"success": True/False, ...}` on all code paths
- [ ] Exceptions handled with `try/except` — server must never crash
- [ ] Unit test added in `tests/`.
- [ ] Dependencies are minimal — reuse existing libraries where possible
- [ ] Tools table updated in `README.md`
- [ ] `mcp.json` updated if applicable
- [ ] `requirements.txt` updated if a new dependency was added
- [ ] `.env.example` updated if a new API key is required

---

## Guidelines

| Rule | Detail |
|---|---|
| **Consistency** | Every tool returns `{"success": True/False, ...}` |
| **Validation** | Always validate inputs before making external calls |
| **Error handling** | Catch exceptions and return `{"success": False, "error": str(e)}` |
| **Dependencies** | Check if a library is already used before adding a new one |
| **Legal** | Use `scanme.nmap.org` for port scanning tests — the only public host officially permitted for Nmap testing |
| **API keys** | Never hardcode keys; always use `os.getenv("YOUR_API_KEY")` |

---

## Questions?

Open an issue on GitHub or reach out on LinkedIn: [Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)
