# Getting Started

Defensive security reference — detection, response, and hardening. Written for SOC analysts, incident responders, and detection engineers who need the query, the Event ID, or the artifact meaning during a shift, not a course.

The [Pentest](../pentest/methodology-and-report-writing.md) section of this repo documents the attacker side of most of what follows. Read them together: [Getting Credentials](../pentest/active-directory/getting-credentials.md) is what you are trying to catch in [SIEM & Log Analysis](siem-and-log-analysis.md), and [ADCS Abuse](../pentest/active-directory/adcs-abuse.md) is what you are hunting for in the certificate-issuance events. Detection engineering is easiest when you have actually run the attack.

**Page index:**

1. [**Threat Intelligence**](threat-intelligence.md) — IOCs vs TTPs, Pyramid of Pain, Diamond Model, ATT&CK, intel lifecycle, enrichment.
2. [**Threat Hunting**](threat-hunting.md) — hypothesis-driven hunting, the hunt loop, worked hunts with SPL/KQL/Sigma.
3. [**Detection Engineering**](detection-engineering.md) — detection-as-code, Sigma, the detection lifecycle, tuning, validation.
4. [**SIEM & Log Analysis**](siem-and-log-analysis.md) — log sources, Windows Event ID reference, Sysmon, SPL and KQL patterns.
5. [**DFIR**](dfir.md) — IR lifecycle, order of volatility, triage collection, disk/memory artifacts, timelining.
6. [**Malware Analysis**](malware-analysis.md) — defensive triage, static/dynamic analysis, YARA, IOC extraction.
7. [**Network Security Monitoring**](network-security-monitoring.md) — Zeek, Suricata, PCAP at scale, encrypted traffic, C2 detection.
8. [**Purple Team & Hardening**](purple-team-and-hardening.md) — adversary emulation, detection gap closure, CIS/STIG, Windows and Linux hardening.

## How defense maps to offense

Every offensive technique leaves one or more of: a process, a file, a registry key, a network connection, an authentication event. Defense is the discipline of making sure at least one of those is (a) prevented, (b) logged, and (c) alerted on.

| Attacker action | Where it shows up | Page |
| --- | --- | --- |
| LLMNR/NBT-NS poisoning (Responder) | Rogue responses on the wire; hash relay auth events | [Purple Team & Hardening](purple-team-and-hardening.md) |
| LSASS credential dumping | Sysmon Event ID 10 (ProcessAccess) with `GrantedAccess` 0x1010/0x1410 | [Threat Hunting](threat-hunting.md) |
| Kerberoasting | 4769 with RC4 encryption type, high volume from one account | [SIEM & Log Analysis](siem-and-log-analysis.md) |
| Lateral movement via SMB/PsExec | 4624 Type 3, 5140/5145, 7045 service install | [SIEM & Log Analysis](siem-and-log-analysis.md) |
| C2 beaconing | Regular-interval outbound connections, Zeek `conn.log` | [Network Security Monitoring](network-security-monitoring.md) |
| Phishing macro payload | `winword.exe` → `powershell.exe` parent/child chain | [Threat Hunting](threat-hunting.md) |

## Core frameworks

* [**MITRE ATT&CK**](https://attack.mitre.org/) — the shared vocabulary. Tactics (the *why*) contain techniques (the *how*), which contain sub-techniques. Use it to label detections, scope hunts, and measure coverage. This is the framework that matters most day to day.
* **Cyber Kill Chain** (Lockheed Martin) — recon → weaponization → delivery → exploitation → installation → C2 → actions on objectives. Coarse, linear, and dated, but still a useful way to communicate "how far in did they get" to non-technical stakeholders.
* [**NIST CSF 2.0**](https://www.nist.gov/cyberframework) — Govern, Identify, Protect, Detect, Respond, Recover. Program-level framing, used for maturity/gap conversations rather than analysis.
* **NIST SP 800-61** — the incident handling lifecycle used in [DFIR](dfir.md).
* **Pyramid of Pain** — tells you which indicators are worth investing in. See [Threat Intelligence](threat-intelligence.md).

## Core toolset

| Tool | Use |
| --- | --- |
| [Sigma](https://github.com/SigmaHQ/sigma) | Vendor-neutral detection rule format; convert to SPL/KQL/Elastic/QRadar |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | The single highest-value Windows telemetry source; needs a curated config |
| [Velociraptor](https://docs.velociraptor.app/) | Fleet-wide live hunting, triage collection, and endpoint forensics |
| [KAPE](https://www.kroll.com/kape) | Fast targeted artifact collection + parsing on Windows |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Memory forensics — see [CTF Forensics](../ctf/forensics-and-steganography.md) for plugin usage |
| [Zeek](https://zeek.org/) | Network transaction logging (the network equivalent of Sysmon) |
| [Suricata](https://suricata.io/) | Signature-based network IDS/IPS + protocol logging |
| [YARA](https://github.com/VirusTotal/yara) | Pattern matching for files and memory |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Small, per-technique attack tests for validating detections |
| [MISP](https://www.misp-project.org/) / [OpenCTI](https://filigran.io/solutions/open-cti/) | Threat intel storage, correlation, and sharing |
| [plaso / log2timeline](https://github.com/log2timeline/plaso) | Super timeline generation |
| [CyberChef](https://gchq.github.io/CyberChef/) | Decode/deobfuscate anything — base64, XOR, gzip, chained |

## Working rules

* **Prevention where possible, detection where not.** A hardening control that removes the technique entirely beats a rule that fires after the fact.
* **A noisy detection is worse than no detection** — it trains analysts to close alerts without reading them.
* **Log what you can query.** Telemetry you never search is storage cost, not security.
* **Every incident should end as a detection.** If you found it manually, codify it before you close the ticket.
