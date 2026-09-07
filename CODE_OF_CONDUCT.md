# Code of Conduct

**AynOps is built to inspect attack surfaces, probe open ports, and audit infrastructure vulnerabilities — not attack the humans building it.** Keep that boundary clear across every issue, pull request, code review, discussion, commit message, and project channel.

---

## The Short Version

Focus on high-signal technical engineering. Disagree about protocols, architectures, and implementation trade-offs as fiercely as you like; never make it personal, condescending, or hostile.

---

## What's Encouraged & Fine

- **Blunt, rigorous technical critique.**  
  *"This socket implementation lacks a read timeout and will cause the MCP server thread to hang on unclosed connections"* or *"This DNS regex silently fails on valid punycode IDNs, here is the RFC-compliant test case"* is exactly the direct, high-value feedback this project wants.
- **Pushing back on architectural and design decisions**, including those made by the core maintainers.
- **Rejecting or closing pull requests** when accompanied by clear technical justification, failed security assumptions, or out-of-scope boundaries.
- **Debating RFC specifications and security threat models** (e.g., SPF/DMARC alignment rules, TLS cipher deprecation thresholds, or async wave concurrency bottlenecks) until a technically sound consensus is reached.

---

## What's Prohibited & Not Fine

- **Personal attacks and ad hominem arguments.**  
  Critique the code, the algorithm, or the test coverage — never the person behind it. *"This function introduces a race condition"* is welcome; *"You clearly don't understand async Python"* is unacceptable.
- **Security elitism, gatekeeping, and condescension.**  
  Cybersecurity has a steep learning curve. Mocking someone's networking knowledge, Python proficiency, or the fact that they are new to open-source contributions will not be tolerated.
- **Weaponizing security knowledge.**  
  Do not use obscure security jargon or complex threat vectors to belittle, confuse, or embarrass other contributors.
- **Submitting bad-faith or malicious code.**  
  Attempting to slip in obfuscated logic, hidden command injections, telemetry backdoors, or unvetted data-exfiltration mechanics is grounds for an immediate, permanent ban.
- **Harassment and toxic behavior in any form.**  
  Repeated unwanted contact, discriminatory remarks, sexualized language, doxxing, threats, or public shaming.
- **Derailing technical discussions.**  
  Trolling, spamming, or hijacking issue threads and PRs to provoke unconstructive arguments.

---

## Scope

This Code of Conduct applies across all project-affiliated digital spaces:
- GitHub Issues, Pull Requests, and Discussions
- Commit messages and code review comments
- Any official AynOps communication channels or project boards that may be established
- Future community platforms officially adopted by the project (e.g., Discord/Slack)
- External spaces when formally representing the AynOps project (e.g., presenting or publishing on behalf of the project)

---

## Reporting & Confidentiality

If you experience or witness behavior that violates these standards, please report it privately rather than escalating public conflict in the issue tracker:

- **GitHub**: [@gaoharimran29-glitch](https://github.com/gaoharimran29-glitch)
- **LinkedIn**: [Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)
- **Email**: `gaoharimran29@gmail.com`

When filing a report, please include:
1. Links to the relevant issue, PR, comment, or commit.
2. A concise explanation of the incident and impact.
3. Any relevant context or screenshots.

All reports will be handled confidentially and promptly. You will not face public retaliation or exposure for reporting conduct violations in good faith.

> [!NOTE]
> For **security vulnerabilities** in the AynOps codebase itself (such as command injection, path traversal, or privilege escalation flaws), please follow our responsible disclosure workflow outlined in [SECURITY.md](SECURITY.md) instead of filing conduct reports.

---

## Enforcement

AynOps is an open-source project maintained by active developers. Enforcement is governed by pragmatic, fair maintainer judgment applied proportionally:

1. **Minor / First-Time Friction**: A direct, private message clarifying project expectations and de-escalating the situation.
2. **Repeated or Unconstructive Behavior**: A formal public warning on the relevant PR or issue thread, with moderation or removal of the offending remarks.
3. **Severe or Malicious Violations** *(Harassment, doxxing, threats, or malicious PRs)*: Immediate, permanent removal and block across all AynOps project repositories and spaces without extended debate.

Maintainers and core contributors are held strictly to the same standard.

---

## Why This Exists

Reconnaissance and offensive/defensive cybersecurity tools often spark intense technical debates regarding scan efficiency, detection mechanics, and responsible disclosure. We are explicit about our standards so that AynOps remains a collaborative, high-signal environment where developers and security researchers can build powerful, reliable open-source tooling without unnecessary toxicity or ego.

---

<div align="center">
  <sub>Adapted in spirit from the <a href="https://www.contributor-covenant.org/">Contributor Covenant</a>, customized to reflect the technical and operational ethos of AynOps.</sub>
</div>
