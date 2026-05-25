# 🔐 CyberSecurity MCP Server

A **Model Context Protocol (MCP) server** that gives Claude real-time cybersecurity reconnaissance capabilities. Instead of manually running tools across different terminals, just tell Claude **"analyze google.com"** and get a complete security breakdown instantly.

Built with [FastMCP](https://github.com/jlowin/fastmcp) and Python.

---

## 🎯 What is this?

Claude by default has **zero native cybersecurity tooling**. No WHOIS. No DNS enumeration. No port scanning. No SSL inspection.

This MCP server fixes that — extending Claude with **real-world security tools** that run live against any domain or IP. Reconnaissance that normally requires multiple specialized tools and 20+ minutes of manual work becomes a single prompt.

This is a **local MCP server** — it runs entirely on your machine. Your data never leaves your computer.

---

## 🛠️ Tools Available

| Tool | Description |
|---|---|
| `whois_lookup` | Domain registration data — owner, registrar, creation date, expiry, name servers |
| `dns_enumeration` | A, AAAA, MX, NS, TXT, CNAME, SOA records + common subdomain brute-forcing |
| `port_scan` | Nmap-powered scanner with service/version detection and security warnings |
| `ssl_inspect` | SSL/TLS certificate — issuer, expiry, cipher strength, SANs, TLS version |
| `tech_stack_detect` | Web server, CMS, JS frameworks, CDN, analytics, and security header scoring |
| `cve_lookup` | Search NVD for known CVEs by software name and version (no API key required) |
| `ip_reputation` | Check if an IP is flagged as malicious via AbuseIPDB (api key requied) |
| `full_recon` | Runs all 5 core tools in parallel and returns combined results for Claude to analyze |

---

## 📸 Demo

### Single tool — CVE lookup
```
You: Look up CVEs for apache 2.4.49

Claude: Found 2 critical CVEs for Apache 2.4.49:
        CVE-2021-41773 (Score: 9.8 CRITICAL) — Path traversal vulnerability
        allowing remote code execution if CGI is enabled. Actively exploited
        in the wild...
```

### Full recon
```
You: Do a complete security recon on reddit.com

Claude: [calls full_recon → runs 5 tools in parallel → delivers full analysis]
```

---

## 📋 Prerequisites

- **Python 3.10+** — [download](https://www.python.org/downloads/)
- **Claude Desktop** — [download](https://claude.ai/download)
- **Nmap** — required for port scanning ([download](https://nmap.org/download.html))
- **Git** — [download](https://git-scm.com/)

---

## ⚙️ Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/gaoharimran29-glitch/Cybersecurity-MCP-Server.git
cd Cybersecurity-MCP-Server
```

### Step 2 — Create a virtual environment

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Mac/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Install Nmap

**Windows:**
1. Download from [nmap.org/download.html](https://nmap.org/download.html) and run the installer
2. Manually add Nmap to PATH:
   - Press `Win + S` → search **"Environment Variables"**
   - Under **System Variables** → find **Path** → click **Edit**
   - Click **New** → add `C:\Program Files (x86)\Nmap`
   - Click OK on all windows
3. Restart your terminal and verify:
```powershell
nmap --version
```

**Mac:**
```bash
brew install nmap
```

**Linux:**
```bash
sudo apt install nmap
```

### Step 5 — Connect to Claude Desktop

Open your Claude Desktop config file:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Mac | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add this configuration:

**Windows:**
```json
{
  "mcpServers": {
    "cybersecurity": {
      "command": "C:\\full\\path\\to\\Cybersecurity-MCP-Server\\.venv\\Scripts\\python.exe",
      "args": ["C:\\full\\path\\to\\Cybersecurity-MCP-Server\\main.py"],
      "env": {
        "ABUSEIPDB_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

**Mac/Linux:**
```json
{
  "mcpServers": {
    "cybersecurity": {
      "command": "/full/path/to/Cybersecurity-MCP-Server/.venv/bin/python3",
      "args": ["/full/path/to/Cybersecurity-MCP-Server/main.py"],
      "env": {
        "ABUSEIPDB_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

> ⚠️ Always use the **full absolute path** to your `.venv` Python executable — not just `python` or `python3`. Claude Desktop may use a different Python installation otherwise.

> **Note:** `ABUSEIPDB_API_KEY` is only required for the `ip_reputation` tool. All other 7 tools work without it. Get a free key at [abuseipdb.com](https://www.abuseipdb.com) (free tier: 1,000 requests/day).

### Step 6 — Restart Claude Desktop

Fully quit and reopen Claude Desktop — closing the window is not enough. Check the system tray and quit from there.

Verify tools are connected by asking Claude:
```
What cybersecurity tools do you have available?
```

Claude should list all 8 tools.

---

## 🚀 Usage

### Basic tool usage

```
Do a WHOIS lookup on example.com
Run DNS enumeration on github.com
Scan ports on scanme.nmap.org
Inspect the SSL certificate of stripe.com
Detect the tech stack of wordpress.org
Look up CVEs for apache 2.4.49
Look up CVEs for log4j 2.14.1
Check the reputation of IP 1.2.3.4
```

### Port scan types

| Type | Description | Speed |
|---|---|---|
| `basic` | Top 100 ports | Fast (~5s) |
| `service` | Service & version detection | Medium (~15s) |
| `os` | OS detection (requires admin) | Medium |
| `full` | All 65535 ports | Slow (~5min) |
| `vuln` | Vulnerability scripts | Slow (~30s) |

```
Scan scanme.nmap.org with service detection
```

### Full recon

```
Do a complete security recon on reddit.com
```

Claude will run all 5 core tools in parallel and deliver a full security analysis.

### Follow-up analysis

```
Based on the recon, what are the top security risks?
What do the open ports mean from an attacker's perspective?
Is this SSL configuration strong enough for a financial services company?
Cross-reference the open ports with known CVEs for the detected services.
```

---

## 🧪 Running Tests

```bash
python -m unittest test_security_tools.py
```

Expected output:
```
...
----------------------------------------------------------------------
Ran tests in 0.001s

OK
```

Tests mock external APIs so no internet connection or API keys are required.

---

## ⚠️ Legal & Ethical Usage

> **Only scan domains and IPs you own or have explicit written permission to scan.**

- WHOIS, DNS, SSL, CVE, and tech stack lookups use **public data** — safe on any domain
- Port scanning should only target **your own infrastructure** or authorized systems
- The only public host officially permitted for Nmap testing is `scanme.nmap.org`
- Unauthorized port scanning may be illegal in your jurisdiction

Intended for:
- Security researchers
- Penetration testers (on authorized targets)
- Developers auditing their own infrastructure
- Students learning cybersecurity concepts

---

## 🗂️ Project Structure

```
Cybersecurity-MCP-Server/
├── main.py                  # MCP server — all 8 tools
├──.env.example              # For API testing
├── test_security_tools.py   # Unit tests with mocked APIs
├── requirements.txt         # Python dependencies
├── Dockerfile               # For deployment
├── contributing.md          # Contribution guide
└── README.md                # This file
```

---

## 🔭 Roadmap

- [ ] Shodan integration — internet-wide device and service search
- [ ] Certificate transparency search — find subdomains via cert logs
- [ ] HTTP security headers deep analyzer
- [ ] Phishing domain detector
- [ ] Multi-domain batch scanning
- [ ] PDF report generation

---

## 🤝 Contributing

Pull requests are welcome! Check [contributing.md](contributing.md) for guidelines and a list of open issues ready to pick up.

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

Built by **Gaohar Imran**
- GitHub: [@gaoharimran29-glitch](https://github.com/gaoharimran29-glitch)
- LinkedIn: [Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)

---

> ⭐ If this project helped you, consider giving it a star on GitHub!