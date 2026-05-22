# 🔐 CyberSecurity MCP Server

A **Model Context Protocol (MCP) server** that gives Claude real-time cybersecurity reconnaissance capabilities. Instead of manually running 6 different tools across different terminals, just tell Claude **"analyze google.com"** and get a complete security recon report — including a professionally generated PDF.

Built with [FastMCP](https://github.com/jlowin/fastmcp) and Python.

---

## 🎯 What is this?

Claude by default has no cybersecurity capabilities. This MCP server extends Claude with **6 real-world security tools** that run live against any domain — giving Claude the ability to perform reconnaissance that would normally require multiple specialized tools and significant manual effort.

This is a **local MCP server** — it runs on your machine and connects to Claude Desktop. Your data never leaves your computer.

---

## 🛠️ Tools Available

| Tool | Description |
|---|---|
| `whois_lookup` | Query domain registration data — owner, registrar, creation date, expiry, name servers |
| `dns_enumeration` | Enumerate A, AAAA, MX, NS, TXT, CNAME, SOA records + brute-force common subdomains |
| `port_scan` | Nmap-powered port scanner with service/version detection and security warnings |
| `ssl_inspect` | Inspect SSL/TLS certificate — issuer, expiry, cipher strength, SANs, TLS version |
| `tech_stack_detect` | Fingerprint web server, CMS, JS frameworks, CDN, analytics, and security headers |
| `full_recon` | Orchestrates all 5 tools in parallel and returns combined results for Claude to analyze |

---

## 📸 Demo

### Single tool — WHOIS lookup
```
You: Do a WHOIS lookup on github.com and tell me what you find

Claude: [calls whois_lookup] GitHub.com is registered through MarkMonitor Inc., 
one of the world's largest domain registrars specializing in brand protection. 
The domain was created in 2007 and is secured until 2026...
```

### Full recon
```
You: Do a complete security recon on reddit.com and generate a PDF report

Claude: [calls full_recon → runs 5 tools in parallel → writes summaries → final output]
```

---

## 📋 Prerequisites

Before installing, make sure you have:

- **Python 3.10+** — [download here](https://www.python.org/downloads/)
- **Claude Desktop** — [download here](https://claude.ai/download)
- **Nmap** — required for port scanning only ([download here](https://nmap.org/download.html))
- **Git** — [download here](https://git-scm.com/)

---

## ⚙️ Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/gaoharimran29-glitch/Cybersecurity-MCP-Server
cd cybersecurity-mcp-server
```

### Step 3 — Install Python dependencies

```bash
pip install fastmcp python-whois dnspython requests python-nmap
```

Or install from requirements.txt:
```bash
pip install -r requirements.txt
```

### Step 4 — Install Nmap (for port scanning)

**Windows:**
1. Download the installer from [nmap.org/download.html](https://nmap.org/download.html)
2. Run the installer
3. Manually add Nmap to PATH:
   - Press `Win + S` → search **"Environment Variables"**
   - Click **"Edit the system environment variables"**
   - Under **System Variables** → find **Path** → click **Edit**
   - Click **New** → add `C:\Program Files (x86)\Nmap`
   - Click OK on all windows
4. Restart your terminal and verify:
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

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "cybersecurity": {
      "command": "python",
      "args": ["C:\\full\\path\\to\\cybersecurity-mcp-server\\main.py"]
    }
  }
}
```

> ⚠️ Replace the path with the actual full path to `main.py` on your machine.
> Replace the python with actual python file path of venv or python.
> On Windows use double backslashes `\\` in the path.

### Step 6 — Restart Claude Desktop

Fully quit and reopen Claude Desktop. You should see a 🔌 icon indicating MCP tools are connected.

To verify, ask Claude:
```
What cybersecurity tools do you have available?
```

Claude should list all 6 tools.

---

## 🚀 Usage

### Basic tool usage

```
Do a WHOIS lookup on example.com
Run DNS enumeration on github.com  
Scan ports on scanme.nmap.org
Inspect the SSL certificate of stripe.com
Detect the tech stack of wordpress.org
```

### Port scan types

The `port_scan` tool supports 5 scan types:

| Type | Description | Speed |
|---|---|---|
| `basic` | Top 100 ports | Fast (~5s) |
| `service` | Service & version detection | Medium (~15s) |
| `os` | OS detection (needs admin) | Medium |
| `full` | All 65535 ports | Slow (~5min) |
| `vuln` | Vulnerability scripts | Slow (~30s) |

```
Scan scanme.nmap.org with service detection
```

### Full recon

```
Do a complete security recon on reddit.com
```

Claude will:
1. Run all 5 tools in parallel
2. Analyze each result
3. Write a summary for each section

### Follow-up analysis

```
Based on the recon report, what are the security risks and what should be fixed first?
Explain what the open ports mean from an attacker's perspective.
Is the SSL configuration strong enough for a financial services company?
```

---

## ⚠️ Legal & Ethical Usage

> **Only scan domains you own or have explicit written permission to scan.**

- WHOIS, DNS, SSL, and tech stack lookups query **public data** — safe on any domain
- Port scanning should only be performed on **your own infrastructure** or authorized targets
- The only public host officially permitted for Nmap testing is `scanme.nmap.org`
- Unauthorized port scanning may be illegal in your jurisdiction

This tool is intended for:
- Security researchers
- Penetration testers (on authorized targets)
- Developers auditing their own infrastructure
- Students learning cybersecurity concepts

---

## 🗂️ Project Structure

```
cybersecurity-mcp-server/
├── main.py              # MCP server — all 6 tools
├── requirements.txt     # Python dependencies
├── README.md            # This file
```

---


## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

Built by **[Gaohar Imran]**
- GitHub: [@gaoharimran29-glitch](https://github.com/gaoharimran29-glitch)
- LinkedIn: [GaoharImran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)

---

> ⭐ If this project helped you, consider giving it a star on GitHub!