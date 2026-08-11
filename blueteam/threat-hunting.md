# Threat Hunting

Hunting is the proactive search for adversary activity that your existing detections did **not** catch. If an alert started it, that's investigation, not hunting.

## Hunting vs alerting

| | Alerting | Hunting |
| --- | --- | --- |
| Trigger | A rule fired | A hypothesis you wrote |
| Input | Single event/correlation | Broad datasets, often weeks of history |
| Output | Verdict on one alert | New detections, new visibility gaps, sometimes an incident |
| Success | Correctly classified | Something changed — a rule shipped, a log source added, an assumption disproved |
| Failure mode | Alert fatigue | Aimless "let's look at some data" with no hypothesis |

**A hunt that finds nothing is not a failed hunt** — provided the hypothesis was falsifiable and you now know that technique is absent (or that you lack the telemetry to say so). "We can't answer this" is a finding: it's a logging gap.

## The hunt loop

1. **Hypothesis** — a specific, falsifiable statement. "An adversary is using `rundll32.exe comsvcs.dll MiniDump` to dump LSASS on our servers."
2. **Data** — identify the exact sources/fields required. If they don't exist, stop and file a telemetry gap.
3. **Analysis** — query, stack, cluster, and filter. Aggregate before you eyeball.
4. **Findings** — malicious, benign-but-noteworthy, or absent. Document either way.
5. **Codify** — turn the successful query into a detection rule ([Detection Engineering](detection-engineering.md)), and turn benign noise into a documented baseline/allowlist.

Then feed the residue back into a new hypothesis.

## Building hypotheses

**From ATT&CK:**

* Pick techniques relevant to your environment and to actors targeting your sector (see [Threat Intelligence](threat-intelligence.md)).
* Prioritize by: likelihood in your stack × your current detection coverage (from your ATT&CK Navigator layer) × impact.
* Rewrite the technique as a testable statement about *your* data: `T1055 Process Injection` → "A process with no signed publisher created a remote thread in `explorer.exe` in the last 30 days" (Sysmon Event ID 8).

**From threat intel:**

* A report describes an actor's loader writing to `C:\ProgramData\<random>\` and persisting via a scheduled task → hunt for scheduled tasks created in the last 90 days whose action path is under `ProgramData`.
* Retro-hunt fresh IOCs across full retention as soon as you receive them; low value long-term, high value in the first 48 hours.

**From the environment:**

* Crown jewels first — domain controllers, certificate authorities ([ADCS abuse](../pentest/active-directory/adcs-abuse.md)), backup servers, jump hosts, source control.
* Anomaly-of-one: stack a behavior across the fleet and look at the rarest values. Most malicious behavior is *rare*, and rarity is queryable when maliciousness isn't.

## Hunt maturity model (Sqrrl HMM)

| Level | Name | Characteristic |
| --- | --- | --- |
| HMM0 | Initial | Relies entirely on automated alerting; little to no routine data collection |
| HMM1 | Minimal | Ingests some telemetry; hunts are IOC searches driven by intel feeds |
| HMM2 | Procedural | Follows hunt procedures published by others; high data collection |
| HMM3 | Innovative | Creates its own hunt procedures and analytics (statistical, ML-assisted) |
| HMM4 | Leading | Automates successful hunts into detections as a matter of course |

The jump that matters is HMM2 → HMM3 (writing your own analytics) and the discipline that defines HMM4 (**every repeatable hunt gets automated**).

## Data requirements per hunt

| Hunt class | Required telemetry |
| --- | --- |
| Process/execution | Sysmon 1 or 4688 **with command line**, EDR process events |
| Credential access | Sysmon 10, 4624/4625/4648/4769, LSASS handle telemetry |
| Persistence | Sysmon 12/13 (registry), 4698 (scheduled task), 7045/4697 (service), autoruns snapshots |
| Lateral movement | 4624 Type 3/10, 5140/5145, Sysmon 3, DNS logs, EDR network events |
| C2 / exfil | Zeek `conn.log`/`dns.log`/`ssl.log`, proxy logs, NetFlow, firewall allow-logs |
| Script execution | PowerShell 4104 script block logging, 4103 module logging, AMSI |

If you can't answer "which index and which field", the hunt isn't scoped yet.

---

## Worked hunts

### 1. LSASS credential access (T1003.001)

**Splunk (Sysmon EID 10):**

```
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| eval ga=lower(GrantedAccess)
| search ga IN ("0x1010","0x1410","0x1438","0x143a","0x1f0fff","0x1fffff")
| search SourceImage!="*\\MsMpEng.exe" SourceImage!="*\\wmiprvse.exe"
| stats count values(GrantedAccess) as access values(CallTrace) as calltrace by Computer, SourceImage
| sort - count
```

**Defender / Sentinel KQL:**

```
DeviceEvents
| where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall")
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "wmiprvse.exe", "csrss.exe", "svchost.exe")
| summarize Hits=count(), Cmds=make_set(InitiatingProcessCommandLine, 5)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Hits desc
```

**Notes:** `0x1010` (VM_READ + QUERY_INFO) and `0x1410` are the classic Mimikatz/procdump patterns; `0x1fffff` is PROCESS_ALL_ACCESS. Also check `CallTrace` for `UNKNOWN(...)` frames — unbacked memory in the call stack is a strong signal of injected/manually mapped code. Legitimate access comes from AV/EDR, `wmiprvse.exe`, and some backup agents — baseline yours before alerting.

### 2. Office spawning a script interpreter (T1566.001 → T1059)

**Splunk:**

```
index=sysmon EventCode=1
  ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\outlook.exe","*\\msaccess.exe")
  Image IN ("*\\powershell.exe","*\\pwsh.exe","*\\cmd.exe","*\\wscript.exe","*\\cscript.exe",
            "*\\mshta.exe","*\\rundll32.exe","*\\regsvr32.exe","*\\certutil.exe","*\\curl.exe","*\\msbuild.exe")
| table _time Computer User ParentImage Image CommandLine
| sort - _time
```

**KQL:**

```
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","msbuild.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

Near-zero false positives in most enterprises. Add Adobe Reader and archive tools (`7zFM.exe`, `winrar.exe`) as parents for the same value.

### 3. Encoded / obfuscated PowerShell (T1059.001, T1027)

**Splunk:**

```
index=sysmon EventCode=1 Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| regex CommandLine="(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s"
| rex field=CommandLine "(?<b64>[A-Za-z0-9+/=]{40,})"
| eval decoded=replace(urldecode(b64),"\x00","")
| table _time Computer User ParentImage CommandLine b64
```

**KQL (decode inline):**

```
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-[eE][ncodema]*\s+[A-Za-z0-9+/=]{40,}"
| extend B64 = extract(@"([A-Za-z0-9+/=]{40,})", 1, ProcessCommandLine)
| extend Decoded = replace_string(base64_decode_tostring(B64), "\u0000", "")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, Decoded, ProcessCommandLine
```

Also hunt on 4104 script block content (`FromBase64String`, `IEX`, `DownloadString`, `-nop -w hidden`, `Invoke-Expression`, backtick-heavy strings, string-concat obfuscation) — see [SIEM & Log Analysis](siem-and-log-analysis.md). PowerShell's abbreviation parsing means `-e`, `-ec`, `-encodedC` all work; regex accordingly.

### 4. Suspicious service creation (T1543.003, T1569.002)

**Splunk (7045 + 4697, stacked for rarity):**

```
index=wineventlog (EventCode=7045 OR EventCode=4697)
| eval svc_path=coalesce(Service_File_Name, ServiceFileName)
| eval short=lower(mvindex(split(svc_path,"\\"),-1))
| stats count dc(Computer) as hosts values(Computer) as computers by short, svc_path
| where hosts <= 3
| sort count
```

Then triage anything with: paths in `\Users\`, `\Temp\`, `\ProgramData\`; `cmd.exe /c` or `powershell` in the image path; random 8-character service names (PsExec/Impacket default patterns); `%COMSPEC%`. Correlate with 4624 Type 3 from the same source in the preceding minute — that's remote service creation, i.e. lateral movement (see [Lateral Movement](../pentest/active-directory/lateral-movement.md)).

### 5. Beaconing detection (T1071)

Beacons are regular. Measure the coefficient of variation of inter-connection intervals: low CV = machine, high CV = human.

**Splunk:**

```
index=network sourcetype=zeek:conn
| fields _time src_ip dest_ip dest_port bytes_out
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev by src_ip dest_ip
| eval delta = _time - prev
| where isnotnull(delta) AND delta > 0
| stats count as conns, avg(delta) as mean_i, stdev(delta) as sd_i,
        dc(bytes_out) as uniq_sizes, sum(bytes_out) as total_out by src_ip dest_ip dest_port
| eval cv = round(sd_i/mean_i, 3)
| where conns >= 24 AND mean_i > 15 AND cv < 0.15
| sort cv
```

**KQL:**

```
DeviceNetworkEvents
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| order by DeviceId, RemoteIP, Timestamp asc
| extend PrevTs = prev(Timestamp), PrevKey = strcat(prev(DeviceId), prev(RemoteIP))
| where PrevKey == strcat(DeviceId, RemoteIP)
| extend Delta = datetime_diff('second', Timestamp, PrevTs)
| summarize Conns=count(), Mean=avg(Delta), SD=stdev(Delta) by DeviceId, DeviceName, RemoteIP, RemoteUrl
| extend CV = SD / Mean
| where Conns >= 24 and Mean > 15 and CV < 0.15
| order by CV asc
```

**Watch for:** jitter defeats naive CV (a 20% jitter setting pushes CV to ~0.12 — keep the threshold loose), and legitimate beacons are everywhere (telemetry, AV updates, NTP, monitoring agents, SaaS keepalives). Baseline and allowlist by destination, not by source. Also stack on near-constant payload sizes (`uniq_sizes` low) and long-duration connections. [RITA](https://github.com/activecm/rita) does this analysis over Zeek logs out of the box — see [Network Security Monitoring](network-security-monitoring.md).

### 6. Rare-parent process stacking (general anomaly hunt)

```
index=sysmon EventCode=1
| eval pair = lower(mvindex(split(ParentImage,"\\"),-1)) . " -> " . lower(mvindex(split(Image,"\\"),-1))
| stats count dc(Computer) as hosts values(Computer) as sample by pair
| where hosts <= 2 AND count <= 5
| sort count
```

Stack-counting is the highest-yield hunting technique that requires no threat intel at all. Apply it to: parent/child pairs, service names, scheduled task names, autorun values, signer names, DLL load paths, User-Agents.

---

## Codify the result

**Sigma rule from hunt #2:**

```yaml
title: Office Application Spawning Script Interpreter
id: 6f2a1e0c-9d4b-4a19-8b62-3f8b0d3c11a7
status: experimental
description: Detects Microsoft Office applications spawning script interpreters or LOLBins, typical of malicious macro or exploit payload execution.
references:
  - https://attack.mitre.org/techniques/T1566/001/
author: blueteam
date: 2026/08/11
tags:
  - attack.execution
  - attack.t1059
  - attack.initial-access
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\msaccess.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\msbuild.exe'
  filter_repair:
    CommandLine|contains: '/repair'
  condition: selection_parent and selection_child and not filter_repair
falsepositives:
  - Office repair and add-in installation routines
  - Line-of-business macros that legitimately shell out (baseline and allowlist by hash/path)
level: high
```

Convert and deploy:

```
sigma convert -t splunk -p sysmon office_spawn_interpreter.yml
sigma convert -t microsoft365defender office_spawn_interpreter.yml
```

## Documenting a hunt

Keep it short and reusable — a hunt nobody can repeat has no value after the shift ends.

- [ ] **Hypothesis** stated in one falsifiable sentence, with ATT&CK technique IDs
- [ ] **Scope** — data sources, indexes, time range, host population
- [ ] **Queries run**, verbatim and copy-pasteable
- [ ] **Findings** — malicious / benign / inconclusive, with evidence
- [ ] **Telemetry gaps** discovered, filed as tickets
- [ ] **Outcome** — detection rule shipped, baseline documented, or hypothesis retired
- [ ] **Repeat cadence** — one-off, or scheduled (and if scheduled, why isn't it a detection yet?)
