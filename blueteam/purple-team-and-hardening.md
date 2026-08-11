# Purple Team & Hardening

## Purple team

Red executes a known technique; blue watches whether the detection fires. The output is a **list of closed gaps**, not a score.

| | Red team | Purple team |
| --- | --- | --- |
| Objective | Test the org's ability to detect an unknown adversary | Test whether a **specific, named** technique is detected |
| Knowledge | Blue doesn't know what/when | Both sides know exactly what and when |
| Output | Report on what got missed | Detections fixed, and re-tested, the same week |
| Cadence | Annual/biannual | Continuous |
| Failure mode | Becomes a scoreboard nobody learns from | Becomes a checkbox exercise with no remediation follow-through |

**The rule:** if a technique isn't detected, the exercise isn't over. You write the detection, redeploy it, and **re-execute the same test** to prove it fires. An untested "we added a rule" is not a closed gap.

### Running an exercise

1. **Scope** — pick 8–15 ATT&CK techniques. Prioritize by relevance (actors targeting your sector, per [Threat Intelligence](threat-intelligence.md)) and by your current coverage gaps.
2. **Plan** — for each technique, record the test procedure, the expected telemetry, and the expected detection. Agree the window, the target hosts, and a rollback/cleanup plan. Get change approval in writing.
3. **Execute** — run one technique at a time, timestamped (UTC). Blue observes without being told which one is running, then compares notes.
4. **Measure** — record the outcome per technique:

| Outcome | Meaning |
| --- | --- |
| **Prevented** | Control blocked it outright — the best result |
| **Alerted** | Detection fired and reached an analyst |
| **Logged only** | Telemetry captured it; no rule existed to fire |
| **No telemetry** | Nothing recorded — a logging gap, the most serious finding |

Also capture: time to detect, time to triage, whether the analyst's runbook was adequate, and whether the alert contained enough context to act on.

5. **Remediate** — logging gaps become telemetry tickets; "logged only" becomes a detection engineering ticket ([Detection Engineering](detection-engineering.md)); noisy detections get tuned.
6. **Retest** — re-run the same atomics after remediation. Then schedule a regression run quarterly, because agent upgrades and config drift silently break detections.

### Atomic Red Team

Small, per-technique tests mapped directly to ATT&CK. The default tool for this work.

```powershell
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser
Import-Module invoke-atomicredteam -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1003.001 -ShowDetailsBrief          # what tests exist
Invoke-AtomicTest T1003.001 -ShowDetails                # full commands + prereqs, review before running
Invoke-AtomicTest T1003.001 -CheckPrereqs
Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1,3            # execute
Invoke-AtomicTest T1003.001 -TestNumbers 1,3 -Cleanup   # always clean up

Invoke-AtomicTest All -ShowDetailsBrief                 # inventory everything available
Invoke-AtomicTest T1059.001 -TestNumbers 1 -TimeoutSeconds 120 -ExecutionLogPath C:\purple\log.csv
```

**Always read `-ShowDetails` before executing.** Some atomics are genuinely destructive (shadow copy deletion, log clearing, service modification). Run on a dedicated test host where possible, and never on a domain controller without an explicit plan.

Linux/macOS: the same atomics run via `Invoke-AtomicTest` under PowerShell Core, or execute the documented commands manually from the technique's `.yaml`.

### CALDERA

MITRE's automated adversary emulation platform — chains techniques into full operations, which tests detections *in sequence* the way they'd actually occur.

```
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip3 install -r requirements.txt
python3 server.py --insecure          # lab only; configure TLS + credentials for anything real
# Deploy the Sandcat agent to a target, then run an adversary profile (e.g. "Discovery", "Hunter")
```

Useful plugins: **Atomic** (imports Atomic Red Team as CALDERA abilities), **Stockpile** (ability library), **Manx** (reverse shell agent), **Response** (automated incident response actions), **Debrief** (reporting).

Alternatives: [Stratus Red Team](https://github.com/DataDog/stratus-red-team) for cloud techniques, [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) for AD-focused emulation, [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) for tracking exercise results over time, plus commercial BAS (AttackIQ, SafeBreach, Picus).

### Tracking gaps with ATT&CK Navigator

Maintain two layers and diff them:

* **Coverage layer** — scored 0–4 per technique (`0` no telemetry, `1` telemetry only, `2` untested detection, `3` validated detection, `4` prevented).
* **Threat layer** — techniques used by the actors relevant to you (Navigator ships built-in group layers).

Overlay them; the techniques scored 0–1 that appear in the threat layer are your work queue, in priority order. Re-score only from **validated** results — a purple team exercise is the only thing that justifies a 3 or 4. Keep layer JSON in git so coverage over time is a diff, not an anecdote.

---

## Hardening

**Hardening beats detection wherever it's available.** A detection is a bet that an analyst will see an alert, understand it, and respond faster than the attacker acts. A control that removes the technique entirely wins that bet every time. Spend the first hour of any project on prevention, and only then build a detection for what's left.

### Baselines and benchmarks

| Standard | Notes |
| --- | --- |
| [**CIS Benchmarks**](https://www.cisecurity.org/cis-benchmarks) | Free, consensus-built, per-platform (Windows, Linux distros, cloud, browsers, databases). Level 1 = safe defaults; Level 2 = defense-in-depth with functionality tradeoffs. Start here |
| **DISA STIGs** | Stricter, US DoD-mandated; more granular and often more aggressive than CIS. Required in defense/gov contexts |
| **Microsoft Security Baselines** | Ships as GPO/Intune policy packs in the [Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319) — the most practical starting point for Windows estates |
| **CIS Benchmark tooling** | CIS-CAT Pro, [OpenSCAP](https://www.open-scap.org/) + SCAP content, [Lynis](https://cisofy.com/lynis/), [ScoutSuite](https://github.com/nccgroup/ScoutSuite)/[Prowler](https://github.com/prowler-cloud/prowler) for cloud |

```
# Linux: assess against a SCAP profile, then generate a remediation script
oscap xccdf eval --profile cis_level1_server \
  --results scan.xml --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
lynis audit system

# Windows: measure GPO drift against a Microsoft baseline
PolicyAnalyzer.exe        # from the Security Compliance Toolkit
```

**Do not apply a benchmark wholesale to production.** Test in a pilot ring, measure breakage, document deviations with a justification, and track exceptions with expiry dates.

### Windows hardening essentials

| Control | What it kills |
| --- | --- |
| **LAPS** (Windows LAPS, built into modern Windows) | Local admin password reuse — the single control that stops estate-wide lateral movement via a shared local admin hash. Enable and audit that it's actually applying |
| **Credential Guard** (VBS) | Pass-the-hash and LSASS credential theft — isolates secrets in a VBS enclave. Requires UEFI, Secure Boot, and modern hardware |
| **LSA Protection** (RunAsPPL) + **LSASS as PPL** | Casual LSASS dumping; forces the attacker into driver-based/BYOVD territory, which is far noisier |
| **ASR rules** (Defender Attack Surface Reduction) | Office spawning child processes, credential theft from LSASS, obfuscated scripts, executable content from email/USB, PSExec/WMI process creation. **Deploy in audit mode first**, review, then block |
| **Disable LLMNR, NBT-NS, mDNS, and WPAD** | **[Responder](../pentest/active-directory/getting-credentials.md) and every NTLM-relay chain that starts with name-resolution poisoning.** This is the highest-value, lowest-cost AD hardening change available. Nothing legitimate should depend on them once DNS is correct |
| **SMB signing required** (clients and servers) | NTLM relay to SMB (`ntlmrelayx`). Set on all hosts, not just DCs |
| **LDAP signing + channel binding** | NTLM relay to LDAP/LDAPS — the path to ADCS ESC8 and RBCD attacks |
| **Disable NTLM** where possible; NTLMv1 always | Relay and downgrade attacks. Audit first with the NTLM auditing policies |
| **Tiered admin model** (Tier 0/1/2) | Credential harvesting from a compromised workstation yielding domain admin. Enforce with authentication silos, Protected Users group, and logon-type restrictions (deny Type 2/10 for Tier 0 accounts on Tier 1/2 hosts) |
| **AppLocker / WDAC** | Arbitrary binary and script execution; WDAC in enforced mode with a good policy is the strongest single endpoint control available. Block the [LOLBAS](https://lolbas-project.github.io/) set explicitly |
| **PowerShell Constrained Language Mode** (via WDAC/AppLocker) | Nearly all offensive PowerShell tooling |
| **Remove PowerShell v2** | Script block logging bypass via downgrade |
| **Protected Users group + no unconstrained delegation** | Kerberos delegation abuse, credential caching on member servers |
| **ADCS hardening** | [ESC1–ESC8 template and enrollment abuse](../pentest/active-directory/adcs-abuse.md) — audit templates for `ENROLLEE_SUPPLIES_SUBJECT`, disable web enrollment over HTTP, require manager approval |
| **Disable Print Spooler** on DCs and servers that don't print | PrintNightmare, and the spooler-based coercion primitives |
| **Block outbound SMB (445) at the perimeter** | Hash leakage via UNC paths in documents and email |
| **Restrict local admin rights** for standard users | The majority of privilege escalation and persistence techniques |
| **Macro policy: block macros from the internet** (and prefer disabling VBA entirely) | The commodity phishing payload chain |
| **BitLocker + Secure Boot** | Offline attacks and physical access |

Verify, don't assume:

```powershell
# Credential Guard / VBS status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus

# LSA protection (1 or 2 = enabled)
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL

# SMB signing (server and client)
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature

# LLMNR / NBT-NS state
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description, TcpipNetbiosOptions   # 2 = disabled

# ASR rule state (1=block, 2=audit, 6=warn)
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# LAPS applying?
Get-LapsADPassword -Identity <computer> -AsPlainText
```

### Linux hardening basics

- [ ] SSH: key-only auth (`PasswordAuthentication no`), `PermitRootLogin no`, restrict by group (`AllowGroups`), non-default port only as noise reduction (not security), and `fail2ban`/`sshguard`
- [ ] Minimize installed packages and running services; every daemon is attack surface (`systemctl list-unit-files --state=enabled`)
- [ ] Host firewall default-deny inbound (`nftables`/`ufw`/`firewalld`), and **egress filtering** on servers — this alone breaks most C2
- [ ] Mandatory access control enabled and enforcing: SELinux (`getenforce` → `Enforcing`) or AppArmor
- [ ] Mount options: `noexec,nosuid,nodev` on `/tmp`, `/var/tmp`, `/dev/shm`, and removable media
- [ ] Audit and minimize SUID/SGID binaries: `find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null`
- [ ] Tight `sudo` policy — no `NOPASSWD: ALL`, no wildcards in command paths, no shell escapes (`vi`, `less`, `find -exec`); see [Linux Privilege Escalation](../pentest/privilege-escalation/linux-privilege-escalation.md) for what a loose policy gives away
- [ ] `auditd` with a real ruleset ([Neo23x0/auditd](https://github.com/Neo23x0/auditd) is a good base) — without it, Linux execution telemetry does not exist
- [ ] Kernel hardening via `sysctl`: `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=1`, `net.ipv4.conf.all.rp_filter=1`, disable unused protocol modules
- [ ] Centralize logs off-host immediately (rsyslog/journald forwarding) — local logs are the first thing cleared
- [ ] Automatic security updates (`unattended-upgrades` / `dnf-automatic`) with a reboot policy that actually results in reboots
- [ ] Containers: non-root user, read-only root filesystem, drop all capabilities and add back only what's needed, no `--privileged`, no docker socket mounts, scan images in CI

### Patch and vulnerability management

Raw CVSS is a poor prioritization signal on its own — it measures theoretical severity, not the likelihood anyone will use it against you. Combine three inputs:

| Input | What it tells you | Use |
| --- | --- | --- |
| [**CISA KEV**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | This vulnerability **is being exploited in the wild**, confirmed | **Patch these first, always.** Non-negotiable tier |
| [**EPSS**](https://www.first.org/epss/) | Probability (0–1) of exploitation in the next 30 days | Rank everything not on KEV. EPSS >0.1 with internet exposure deserves urgency; a CVSS 9.8 with EPSS 0.0004 usually does not |
| **CVSS** | Theoretical severity and impact if exploited | Use the **environmental** score, and only after KEV/EPSS triage |

**Then weight by your context**, which no public score knows: is the asset internet-facing, does it hold regulated data, is a compensating control in place, is it a Tier 0 system? An internal-only CVSS 7.5 on a domain controller outranks an internet-facing 9.8 on a static marketing site.

```
# EPSS score for a CVE
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2026-12345" | jq '.data[]'

# Is it on KEV?
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r '.vulnerabilities[] | select(.cveID=="CVE-2026-12345")'
```

**Program essentials:**

- [ ] **Asset inventory first** — you cannot patch what you don't know exists, and unknown assets are where breaches start
- [ ] Defined SLAs by tier (KEV/actively-exploited: days; critical internet-facing: 7 days; internal high: 30 days), with measurement and exception tracking
- [ ] Emergency out-of-band process for actively-exploited edge devices (VPN, firewall, file transfer appliances) — these are the current initial-access favorites and routinely go from disclosure to mass exploitation in under 72 hours
- [ ] Track **mean time to remediate**, not vulnerability count; the count only ever goes up
- [ ] Compensating controls (WAF rule, segmentation, feature disable) are valid short-term when patching would cause an outage — but they need an expiry date and a ticket
- [ ] Include the things scanners miss: firmware, hypervisors, network gear, OT, container base images, and third-party libraries in your own code (SCA/SBOM)

### Where hardening beats detection

| Instead of detecting | Prevent it |
| --- | --- |
| Responder/LLMNR poisoning attempts on the wire | Disable LLMNR/NBT-NS/WPAD — the attack simply doesn't work |
| NTLM relay chains | Require SMB signing and LDAP channel binding |
| Malicious macro execution | Block macros from the internet; remove VBA where possible |
| LSASS dumping tools | Credential Guard + RunAsPPL + ASR credential-theft rule |
| Local admin hash reuse across the estate | LAPS |
| Arbitrary LOLBAS execution | WDAC/AppLocker with an explicit LOLBAS deny list |
| Exposed RDP brute force | Remove RDP from the internet; require VPN + MFA + Network Level Authentication |
| Legacy protocol downgrade attacks | Disable SMBv1, NTLMv1, TLS 1.0/1.1, PowerShell v2 |

Detection is what you build for everything left after this list. Build both — but build this list first.
