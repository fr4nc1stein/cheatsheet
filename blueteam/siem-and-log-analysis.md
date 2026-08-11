# SIEM & Log Analysis

## Log sources, in priority order

| Priority | Source | Why |
| --- | --- | --- |
| 1 | **EDR / Sysmon process telemetry** | Process creation with full command line answers most questions; nothing else substitutes |
| 2 | **Windows Security log (DCs + servers + workstations)** | Authentication is the spine of every intrusion — 4624/4625/4768/4769 |
| 3 | **PowerShell script block logging (4104)** | Attackers live in PowerShell; without 4104 you see `-enc <blob>` and nothing else |
| 4 | **DNS (Sysmon 22, DNS server analytical, or resolver logs)** | Cheap, high-signal; every C2 and most exfil touches DNS |
| 5 | **Proxy / web gateway** | URL, User-Agent, bytes, and the user identity behind egress |
| 6 | **Firewall allow-logs (not just denies)** | Denies tell you what was blocked; allows tell you what got out |
| 7 | **Identity provider** (Entra ID / Okta sign-in + audit) | Where modern initial access actually happens — token theft, MFA fatigue, illicit consent |
| 8 | **Cloud control plane** (CloudTrail, Entra audit, GCP Audit) | Attacker actions in cloud leave no host telemetry at all |
| 9 | **Zeek / NetFlow** | Fills the east-west gap and survives host log tampering — see [Network Security Monitoring](network-security-monitoring.md) |
| 10 | Email gateway, VPN, DHCP, AV, app logs | Context and attribution (IP→host→user) |

**DHCP + VPN logs are not optional** — without them you cannot map an IP to a host to a user at a point in time, and every network finding stalls.

## Windows Event ID reference

### Authentication and accounts (Security log)

| ID | Event | Notes for the analyst |
| --- | --- | --- |
| **4624** | Successful logon | Check **Logon Type** (below), `LogonProcessName`, `AuthenticationPackageName` (NTLM vs Kerberos), `IpAddress`, and `LogonId` (correlates to other events in the session) |
| **4625** | Failed logon | `Status`/`SubStatus` gives the reason (below). Spray = many users, few attempts; brute = one user, many attempts |
| **4634** / **4647** | Logoff / user-initiated logoff | Session duration when paired with 4624 by `LogonId` |
| **4648** | Logon using **explicit credentials** | `runas`, `PsExec -u`, `net use /user:` — strong lateral movement and credential-reuse signal. Shows both the source and target account |
| **4672** | Special privileges assigned to new logon | Effectively "an admin just logged on" — pairs with 4624 by `LogonId` |
| **4720** | User account created | On a workstation or DC outside IT change windows, this is persistence |
| **4722 / 4725 / 4726** | Account enabled / disabled / deleted | |
| **4723 / 4724** | Password change (self) / **reset by another user** | 4724 without a helpdesk ticket = takeover |
| **4738** | User account changed | Watch for `UserAccountControl` changes — e.g. "DONT_REQUIRE_PREAUTH" set (enables AS-REP roasting) |
| **4740** | Account locked out | Also a byproduct of spraying, or of stale creds in a service |
| **4728 / 4729** | Member added / removed — **global** security group | Domain Admins, Enterprise Admins → alert unconditionally |
| **4732 / 4733** | Member added / removed — **local** security group | Local Administrators on a server = privilege persistence |
| **4756 / 4757** | Member added / removed — **universal** security group | |
| **4776** | NTLM credential validation (on the DC) | Error `0xC0000064` unknown user, `0xC000006A` bad password |
| **4798 / 4799** | Local group membership enumerated | Recon (`net localgroup administrators`, BloodHound collection) |

**Logon types (4624/4625 field `LogonType`):**

| Type | Meaning | Typical use |
| --- | --- | --- |
| 2 | Interactive | Console logon (or a stolen physical session) |
| 3 | **Network** | SMB, WMI, PsExec, most lateral movement |
| 4 | Batch | Scheduled task |
| 5 | Service | Service account starting a service |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Password sent in the clear — IIS basic auth; rare and worth checking |
| 9 | **NewCredentials** | `runas /netonly` — heavily used with stolen creds / pass-the-hash tooling |
| 10 | **RemoteInteractive** | RDP |
| 11 | CachedInteractive | Cached domain creds (laptop off-network) |

**Common 4625 SubStatus codes:**

| Code | Meaning |
| --- | --- |
| `0xC0000064` | Username does not exist — **user enumeration** when seen in volume |
| `0xC000006A` | Correct username, **wrong password** — spraying/brute forcing |
| `0xC0000234` | Account locked out |
| `0xC0000072` | Account disabled |
| `0xC0000070` | Workstation restriction |
| `0xC000006F` / `0xC0000193` | Logon outside permitted hours / account expired |
| `0xC0000071` | Password expired |
| `0xC0000133` | Clock skew (>5 min) — also a sign of a rogue/misconfigured host |

### Kerberos (Domain Controllers)

| ID | Event | Detection value |
| --- | --- | --- |
| **4768** | TGT requested (AS-REQ) | `PreAuthType 0` = **AS-REP roasting** target. `TicketEncryptionType 0x17` (RC4) where AES is expected = downgrade |
| **4769** | Service ticket requested (TGS-REQ) | **Kerberoasting**: `TicketEncryptionType 0x17` (RC4-HMAC) + `ServiceName` that is a user account + many distinct SPNs from one account in a short window |
| **4771** | Kerberos pre-authentication failed | `FailureCode 0x18` = bad password (the Kerberos equivalent of 4625/`0xC000006A`); `0x12` = disabled/locked/expired |
| **4770** | Service ticket renewed | |
| **4964** | Special groups assigned to logon | Custom watchlist of sensitive groups |

Encryption types: `0x17` RC4-HMAC, `0x11` AES128, `0x12` AES256. **RC4 tickets in an AES environment are the Kerberoasting tell.** See [Getting Credentials](../pentest/active-directory/getting-credentials.md) for the attacker's view.

### Execution, services, tasks, shares

| ID | Log | Event | Notes |
| --- | --- | --- | --- |
| **4688** | Security | Process creation | **Must enable "Include command line in process creation events"** (`Administrative Templates > System > Audit Process Creation`) or the field is empty and the event is near-useless. Includes `ParentProcessName` and, since Win10, `MandatoryLabel` |
| **4689** | Security | Process termination | Rarely worth the volume |
| **4697** | Security | Service installed | Requires "Audit Security System Extension"; includes `ServiceFileName` and `ServiceAccount` |
| **7045** | System | Service installed | Always on by default — the reliable one. PsExec/Impacket leave random 8-char service names here |
| **7034 / 7036 / 7040** | System | Service crashed / state change / start type changed | 7040 to "disabled" on a security service = defense evasion |
| **4698 / 4699 / 4702** | Security | Scheduled task created / deleted / updated | Includes the full task XML — read the `<Command>` and `<Arguments>` |
| **4657** | Security | Registry value modified | Requires SACLs on the keys you care about (Run keys, Winlogon, service ImagePath) |
| **5140** | Security | Network **share** accessed | `ShareName` `\\*\C$`, `ADMIN$`, `IPC$` from a workstation = lateral movement |
| **5145** | Security | Detailed share object access check | Per-file access within a share — high volume, but the only way to see *what file* was taken over SMB |
| **5142 / 5143 / 5144** | Security | Share created / modified / deleted | |
| **5156 / 5157** | Security | WFP permitted / blocked a connection | Host firewall connection log; noisy but useful where there's no EDR |

### Anti-forensics and log integrity

| ID | Log | Event |
| --- | --- | --- |
| **1102** | Security | **Audit log was cleared** — alert at critical, always, no exceptions |
| **104** | System | System/other event log cleared |
| **1100** | Security | Event log service shut down |
| **4719** | Security | System audit policy changed (`auditpol /clear`, `/remove`) |
| **4616** | Security | System time changed — timestomping the log itself |
| **1116/1117/1118** | Defender Operational | Malware detected / action taken / remediation |
| **5001 / 5010 / 5012** | Defender Operational | Real-time protection disabled / config changed |

### Sysmon

The single highest-value Windows source. Install with a curated config — the default config logs almost nothing useful, and "log everything" will bury you.

| ID | Event | Primary use |
| --- | --- | --- |
| **1** | Process creation | Command line, parent, **hashes**, signature status, `OriginalFileName` (survives renaming — use it in rules) |
| **2** | File creation time changed | Timestomping (T1070.006) |
| **3** | Network connection | Process→destination attribution, which 4688 and firewall logs can't give you |
| **5** | Process terminated | Session reconstruction |
| **6** | Driver loaded | BYOVD (bring-your-own-vulnerable-driver), rootkits — check signature and hash |
| **7** | Image (DLL) loaded | **DLL sideloading/hijacking**: a signed EXE loading an unsigned DLL from `\Users\` or `\Temp\`. High volume — filter carefully |
| **8** | CreateRemoteThread | Classic process injection (T1055) |
| **9** | RawAccessRead | Raw `\\.\C:` volume access — NTDS/SAM theft, shadow copy abuse |
| **10** | ProcessAccess | **LSASS handle access** — `TargetImage` `\lsass.exe` + `GrantedAccess` `0x1010`/`0x1410`/`0x1fffff`. Check `CallTrace` for `UNKNOWN(` frames |
| **11** | FileCreate | Dropped payloads, staging archives, web shells in web roots |
| **12/13/14** | Registry key/value create-delete / set / rename | Run keys, service `ImagePath`, Winlogon, IFEO, COM hijacks |
| **15** | FileCreateStreamHash | Alternate data streams, `Zone.Identifier` (mark-of-the-web on downloaded files) |
| **17/18** | Named pipe created / connected | Cobalt Strike and Impacket default pipe names; SMB-based C2 |
| **19/20/21** | WMI event filter / consumer / binding | WMI persistence (T1546.003) — rare and almost always worth reading |
| **22** | **DNS query** | Per-process DNS attribution: the cheapest, highest-yield C2 and tunneling telemetry on Windows |
| **23 / 26** | File delete (archived) / file delete detected | Anti-forensics; 23 keeps a copy of the deleted file |
| **25** | Process tampering | Process hollowing / herpaderping |
| **27/28/29** | File block executable / block shredding / executable detected | Sysmon's small preventive surface |

**Config baselines:** start from [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (well-commented, conservative) or [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular) (modular, ATT&CK-tagged, generate a merged config per environment). Neither is drop-in — tune exclusions to your estate, and **version-control the config** so you know which telemetry existed at any past date. Verify with `sysmon -c` and monitor Event ID 16 (config change) as a tamper signal.

```
sysmon64.exe -accepteula -i sysmonconfig.xml    # install
sysmon64.exe -c sysmonconfig.xml                # update config
sysmon64.exe -c                                 # dump current config
```

## PowerShell logging

Without these, an attacker's PowerShell is a base64 blob you can't read.

| Log | Event ID | What you get |
| --- | --- | --- |
| **Script Block Logging** | **4104** (Microsoft-Windows-PowerShell/Operational) | The **deobfuscated script text** as executed — after decoding, after string concatenation. The single most important PowerShell setting. Level `Warning` fires on suspicious blocks even when logging is off |
| **Module Logging** | **4103** | Pipeline execution details and parameter values per module |
| **Transcription** | (text files) | Full session transcript including output, written to a directory — set a write-only, centrally-collected share |
| Classic engine log | 400 / 403 / 600 | Engine start/stop and provider start; `HostName` reveals non-`ConsoleHost` hosts (i.e. PowerShell run from inside another process) |

Enable via GPO: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. Also deploy **AMSI** (on by default with Defender) and **Constrained Language Mode** via WDAC/AppLocker where you can — it removes most offensive PowerShell tooling outright.

**Caveat:** PowerShell v2 has no script block logging. Remove the v2 engine (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`) and alert on 400 events with `EngineVersion=2.*` — downgrade to v2 is a standard evasion.

## Splunk SPL patterns

```
# Basics: search terms → transforms, piped left to right
index=wineventlog EventCode=4625 earliest=-24h
| stats count by Account_Name, src_ip, Sub_Status
| where count > 10 | sort - count

# Password spray: many DISTINCT accounts failing from one source, few attempts each
index=wineventlog EventCode=4625 earliest=-1h
| stats dc(Account_Name) as users, count as attempts, values(Account_Name) as targets by src_ip
| where users >= 10 AND attempts/users < 5

# Kerberoasting: RC4 service tickets, many distinct SPNs from one account
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| search Service_Name!="*$" 
| stats dc(Service_Name) as spns, values(Service_Name) as services by Account_Name, src_ip
| where spns >= 5

# tstats over an accelerated data model — orders of magnitude faster; use for wide hunts
| tstats summariesonly=t count from datamodel=Endpoint.Processes
  where Processes.process_name="rundll32.exe"
  by Processes.dest, Processes.parent_process_name, Processes.process
| rename "Processes.*" as *

# rare / stack counting — the workhorse for anomaly hunting
index=sysmon EventCode=1 | rare limit=30 Image
index=sysmon EventCode=7 | stats dc(Computer) as hosts count by ImageLoaded | where hosts<=2

# streamstats for time-delta analysis (beaconing, rapid successive logons)
index=zeek sourcetype=conn | sort 0 id_orig_h id_resp_h _time
| streamstats current=f last(_time) as prev by id_orig_h id_resp_h
| eval delta=_time-prev | stats count avg(delta) as mean stdev(delta) as sd by id_orig_h id_resp_h
| eval cv=sd/mean | where count>20 AND cv<0.15

# First-seen detection (new value for an entity)
index=wineventlog EventCode=4624 earliest=-30d
| stats earliest(_time) as first_seen by Account_Name, ComputerName
| where first_seen > relative_time(now(), "-24h")

# Enrich with a lookup (asset owner, criticality, known-good list)
... | lookup asset_inventory host OUTPUT owner, criticality | where criticality="crown_jewel"
```

**Performance:** put index/sourcetype/time constraints first, use `tstats` against accelerated data models for anything spanning weeks, avoid leading wildcards (`*evil`), and prefer `fields` early to drop what you don't need.

## Elastic / Defender KQL patterns

Microsoft Defender XDR advanced hunting and Sentinel share KQL; Elastic uses its own ES|QL/EQL but the shapes translate.

```
// Core tables (Defender XDR): DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
// DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents,
// IdentityLogonEvents, EmailEvents, CloudAppEvents, AlertEvidence

DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

// summarize = stats; make_set/make_list collect values
DeviceLogonEvents
| where Timestamp > ago(1d) and ActionType == "LogonFailed"
| summarize Users=dcount(AccountName), Attempts=count(), Targets=make_set(AccountName, 20)
    by RemoteIP
| where Users >= 10 and Attempts / Users < 5

// join across tables: process → the network connection it made
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| project DeviceId, ProcessId=ProcessId, PCmd=ProcessCommandLine, PTime=Timestamp
| join kind=inner (
    DeviceNetworkEvents
    | project DeviceId, InitiatingProcessId, RemoteIP, RemoteUrl, NTime=Timestamp
  ) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where NTime between (PTime .. PTime + 5m)

// first-seen / rarity
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize FirstSeen=min(Timestamp), Hosts=dcount(DeviceId) by FolderPath
| where FirstSeen > ago(1d) and Hosts <= 2

// external data / watchlist join for IOC sweeps
let badIPs = externaldata(ip:string) [@"https://internal/iocs/ips.csv"] with (format="csv");
DeviceNetworkEvents | where RemoteIP in (badIPs)
```

**Useful operators:** `has` (token match, indexed and fast) beats `contains` (substring scan); `=~` is case-insensitive equality; `in~` case-insensitive list; `parse`/`extract` for regex; `bin(Timestamp, 1h)` for time bucketing; `arg_max()` for latest-per-entity.

## Retention and "good logging"

| Data | Practical minimum |
| --- | --- |
| Security/auth events, EDR process telemetry | 12 months searchable (dwell time routinely exceeds 90 days) |
| Network flow / DNS / proxy | 90 days hot, 12 months cold |
| Cloud control plane audit | 12 months minimum; often a regulatory requirement |
| Full PCAP | 3–7 days rolling — sufficient because Zeek logs cover the long tail |

**Good logging looks like:** centralized (host logs deleted locally are still in the SIEM), time-synchronized to a trusted source, normalized to a schema (ECS/OCSF/CIM) so one query works across sources, complete on **crown-jewel systems specifically** (DCs, CA, backup, jump hosts), and continuously monitored for **ingestion gaps** — an agent that stopped reporting is either broken or disabled by an attacker, and both need an alert.

```
# Alert on log source silence — one of the most valuable rules you will ever write
| tstats latest(_time) as last by host, sourcetype
| eval mins = round((now()-last)/60)
| where mins > 120
| sort - mins
```

## Common blind spots

* **4688 without command line** — the audit policy sub-setting is separate; verify on a real event, not in the GPO editor.
* **Workstations not forwarded** — initial access lands on endpoints, and this is where most orgs only collect from servers.
* **East-west traffic** — everything is inspected at the perimeter and nothing between VLANs. See [NSM sensor placement](network-security-monitoring.md).
* **Encrypted egress with no TLS inspection or JA3/JA4 logging** — C2 becomes an opaque tunnel.
* **Cloud/SaaS/identity logs off or under-retained** — Entra sign-in logs beyond default retention require a diagnostic setting to a workspace.
* **Linux hosts with no auditd/EDR** — frequently the pivot point precisely because they're unmonitored.
* **Domain controllers with default audit policy** — 4769/4768 aren't there unless Kerberos auditing is enabled.
* **Network devices, hypervisors, backup appliances, OT** — ransomware crews target ESXi and backup servers first, and they're usually the least-logged systems in the estate.
* **The SIEM's own audit log** — who changed a rule, deleted an index, or disabled forwarding?
