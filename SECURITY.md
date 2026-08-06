# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest (`main` branch) | ✅ Yes |
| Older releases/commits | ❌ No |

---

## Reporting Security Issues

Security contributions are always welcome.

### Public GitHub Issues

Feel free to open a GitHub Issue or Pull Request for:

- Security improvements or hardening suggestions
- Dependency security updates
- Documentation improvements related to security
- Potential security concerns that are not immediately exploitable
- Questions about the project's security

### Private Disclosure

If you believe you've discovered a vulnerability that could put users at risk (for example, arbitrary code execution, command injection, credential exposure, or another exploitable security issue), please report it privately instead of creating a public issue.

You can report privately through:

- GitHub Private Security Advisory
- Email: gaoharimran29@gmail.com

When reporting, please include:

- Description of the issue
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

I aim to acknowledge reports within **72 hours** and will work toward a fix before public disclosure whenever possible.

---

## Scope

This project is a local MCP server that runs on the user's own machine and does not expose network services by default.

### In Scope

- Command injection or arbitrary code execution
- Path traversal or unsafe file access
- Input validation issues
- Dependency vulnerabilities with practical exploitability
- Security issues within the project's codebase and bundled MCP tools

### Out of Scope

- Security issues in third-party services or APIs
- Availability or rate-limiting of external services
- User-specific operating system or environment configuration
- Security of third-party applications used alongside this project
- Social engineering attacks

---

## Responsible Use

This project is intended for authorized security research and defensive purposes only.

Always ensure you have permission before scanning or testing systems you do not own or administer.

Thank you for helping make the project safer for everyone.
