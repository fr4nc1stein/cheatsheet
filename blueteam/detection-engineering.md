# Detection Engineering

Building, testing, and maintaining detections as an engineering discipline — versioned, tested, and measured — rather than clicking rules into a SIEM console and hoping.

## Detection-as-code

Treat every rule like application code:

* **Version control** — rules live in git, not in the SIEM UI. The SIEM is a deployment target, not the source of truth.
* **Code review** — a second engineer reviews logic, FP potential, and ATT&CK mapping before merge.
* **CI/CD** — pipeline validates YAML schema, runs `sigma convert` for each backend, executes unit tests against sample events, and deploys on merge.
* **Testing** — every rule ships with true-positive sample events and, ideally, an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test that triggers it.
* **Metrics** — track fire count, true/false positive ratio, and time-to-triage per rule. Rules with no data are rules you cannot manage.

```
detections/
├── windows/
│   ├── process_creation/
│   │   ├── proc_creation_win_lsass_dump_comsvcs.yml
│   │   └── tests/proc_creation_win_lsass_dump_comsvcs_test.json
│   └── registry/
├── network/
├── cloud/
└── .github/workflows/validate.yml
```

## Sigma rule anatomy

[Sigma](https://github.com/SigmaHQ/sigma) is the vendor-neutral detection format — write once, convert to any backend. Log source taxonomy and field names come from the Sigma spec, not from your SIEM.

| Field | Required | Purpose |
| --- | --- | --- |
| `title` | yes | Short, describes the behavior — not the tool. Max ~50 chars |
| `id` | yes | UUIDv4, stable forever; the rule's identity across renames |
| `status` | no | `experimental` → `test` → `stable` → `deprecated`/`unsupported` |
| `description` | yes | What it detects and why that's suspicious |
| `references` | no | ATT&CK page, blog post, or report that motivated it |
| `author`, `date`, `modified` | no | Provenance |
| `tags` | no | `attack.<tactic>`, `attack.tXXXX.XXX`, `cve.YYYY-NNNNN` |
| `logsource` | yes | `category` / `product` / `service` — determines field names and which pipeline applies |
| `detection` | yes | Named search identifiers + a `condition` combining them |
| `falsepositives` | yes | Known benign causes — this is what the analyst reads at 3am |
| `level` | yes | `informational` / `low` / `medium` / `high` / `critical` |
| `fields` | no | Fields the analyst should see in the alert |

**Modifiers:** `|contains`, `|startswith`, `|endswith`, `|re`, `|base64offset|contains`, `|all`, `|windash`, `|cidr`, `|lt`/`|gt`. Lists inside one identifier are **OR**; separate keys within an identifier are **AND**.

### Worked example

```yaml
title: LSASS Memory Dump via comsvcs.dll MiniDump
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
status: test
description: >
  Detects credential dumping of the LSASS process using the exported MiniDump function of
  comsvcs.dll executed via rundll32. This is a fileless alternative to procdump/Mimikatz and
  is commonly used immediately after privilege escalation.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/
author: blueteam
date: 2026/08/11
modified: 2026/08/11
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\rundll32.exe'
    - OriginalFileName: 'RUNDLL32.EXE'
  selection_cli:
    CommandLine|contains|all:
      - 'comsvcs'
      - '#'
    CommandLine|contains:
      - 'MiniDump'
      - 'minidump'
  selection_generic:
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'full'
  filter_main_sccm:
    ParentImage|startswith: 'C:\Windows\CCM\'
  condition: selection_img and (selection_cli or selection_generic) and not filter_main_sccm
fields:
  - CommandLine
  - ParentImage
  - User
  - Computer
falsepositives:
  - Legitimate crash-dump tooling invoking comsvcs (rare; validate parent process and signer)
level: critical
```

**Pair it with a second, wider rule** on Sysmon EID 10 (`TargetImage` ending `\lsass.exe`, suspicious `GrantedAccess`) so that a renamed binary or a different dumping method still trips something. One technique, several independent detections at different fidelities — that's defence in depth for detections.

## Conversion to backend queries

```
pip install sigma-cli
sigma plugin list
sigma plugin install splunk elasticsearch microsoft365defender sentinel-asim

# Convert with a field-mapping pipeline (essential — raw conversion won't match your schema)
sigma convert -t splunk -p sysmon rules/proc_creation_win_lsass_comsvcs.yml
sigma convert -t esql   -p ecs_windows rules/
sigma convert -t microsoft365defender rules/
sigma convert -t splunk -p sysmon -f savedsearches rules/   # deployable Splunk artifact

# Validate before converting — catches schema errors and bad ATT&CK tags
sigma check rules/
```

`sigmac` is the legacy converter (pySigma's `sigma-cli` replaced it); you'll still see it referenced in older documentation. **Pipelines matter more than backends** — the same rule against Sysmon, Windows Security, and an EDR needs three different field mappings, and getting that wrong produces a rule that converts cleanly and never fires.

## Detection lifecycle

| Stage | Work | Exit criteria |
| --- | --- | --- |
| **Idea** | From a hunt, incident, intel report, ATT&CK gap, or purple team finding | Technique identified; hypothesis written |
| **Research** | Understand the technique's variants and invariants. Run it in a lab. What *must* be true for it to work? | You know which field/value is unavoidable for the attacker |
| **Build** | Write the Sigma rule; pick the highest-fidelity anchor, not the most obvious string | Rule converts cleanly for every deployed backend |
| **Test** | Trigger with Atomic Red Team / manual execution; confirm it fires. Run against 30+ days of production data for FP volume | TP confirmed; FP rate acceptable |
| **Deploy** | Ship via CI. Start in log-only/monitor mode if volume is uncertain | In production with an owner and a documented response |
| **Tune** | Refine filters based on real FPs. Every exclusion documented with a reason | FP rate within SLA; exclusions reviewed |
| **Retire** | Technique obsolete, tool decommissioned, or replaced by a better rule | Rule deprecated in git, disabled in SIEM, documented |

**Every rule needs an owner and a runbook.** A firing alert with no documented response is an alert that gets closed as "no action taken."

## Detect TTPs, not IOCs

The attacker controls the IOC. They do not fully control the behavior.

| Weak (brittle) | Strong (durable) |
| --- | --- |
| Hash of `mimikatz.exe` | Any process opening a handle to `lsass.exe` with `0x1010`/`0x1410` access |
| `Image|endswith: '\psexec.exe'` | Service created with a random 8-char name from a remote Type 3 logon |
| C2 IP `185.220.101.5` | Regular-interval outbound beacon with low payload-size variance |
| String `Invoke-Mimikatz` | 4104 script block containing `[Reflection.Assembly]::Load` + `VirtualAlloc` |
| Filename `svchost_.exe` in `\Temp\` | `svchost.exe` running from a path other than `System32`/`SysWOW64`, or with a non-`services.exe` parent |

**Find the invariant.** Ask: what would the attacker have to give up to evade this rule? If the answer is "rename a file", the rule is worth little. If it's "stop using this technique class", it's worth a lot.

## Alert tuning and false-positive management

A noisy detection is worse than no detection: it consumes analyst hours, trains the team to close alerts unread, and provides false assurance on a coverage report.

**Rules of engagement:**

* **Never tune by suppressing the alert wholesale.** Tune by adding a *specific, documented* exclusion (this parent process, this signed binary, this service account, this host group) — and put the reason in the rule.
* Exclusions are an attack surface. `CommandLine|contains: 'backup'` is a filter an attacker can satisfy trivially. Scope filters to things the attacker cannot control: signer, parent process ancestry, host group, source subnet.
* **Alert volume budget:** decide up front how many alerts/day the team can actually work. A rule that exceeds its share gets tuned or downgraded to hunting/enrichment data — not left firing.
* **Fidelity tiers:** critical rules page a human; medium rules go to a queue; low-fidelity signals become *enrichment* or *risk score contributors*, not standalone alerts. Risk-based alerting (aggregate several weak signals per entity, alert on the aggregate) resolves most "useful but too noisy" rules.
* **Review cadence:** monthly, pull fire counts per rule. Zero fires in 90 days = broken or dead (verify with a test, don't assume it's just quiet). Highest-firing rules = tuning candidates.

```
# Splunk: which detections are firing and how often (last 30 days)
index=notable earliest=-30d
| stats count, dc(host) as hosts, latest(_time) as last by search_name
| eval last=strftime(last,"%F %T")
| sort - count

# Find rules that have never fired
| rest /servicesNS/-/-/saved/searches splunk_server=local
| search alert.severity>0 | fields title
| join type=left title [ search index=notable earliest=-90d | stats count by search_name | rename search_name as title ]
| where isnull(count)
```

## Validation and testing

**[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** — small, per-technique tests mapped to ATT&CK. The fastest way to answer "does this rule actually fire?"

```powershell
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module invoke-atomicredteam -Force

Invoke-AtomicTest T1003.001 -ShowDetailsBrief      # list the tests
Invoke-AtomicTest T1003.001 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 3         # execute one
Invoke-AtomicTest T1003.001 -TestNumbers 3 -Cleanup
```

**[CALDERA](https://github.com/mitre/caldera)** — MITRE's automated adversary emulation platform. Chains techniques into full operations with an agent (Sandcat), so you test detections in sequence rather than in isolation — which is how they'll actually be encountered.

Others: [Atomic Red Team + AttackIQ/SafeBreach/Prelude](https://github.com/preludeorg) for commercial BAS, [Stratus Red Team](https://github.com/DataDog/stratus-red-team) for cloud techniques, [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) for AD-focused emulation.

**Test discipline:**

* Test in production or a high-fidelity replica — a lab with different logging config proves nothing about production.
* Record the **detection outcome per test**: prevented / alerted / logged only / no telemetry. Those four buckets are the whole point.
* Announce destructive tests. Get change approval. Clean up.
* Re-run tests after agent upgrades and config changes — silent detection regressions are extremely common.

## Coverage measurement

* Tag every rule with its ATT&CK technique ID; export to an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer and score it.
* Score honestly — **validated** coverage only. A rule that exists but has never been tested is score 2, not 3:
  * `0` no telemetry, `1` telemetry only, `2` untested detection, `3` detection validated by purple team, `4` prevented outright.
* Overlay a threat actor's technique layer (Navigator has built-in group layers) on your coverage layer to see which of *their* techniques you'd miss.
* Beware coverage theatre: 300 rules concentrated on Execution while Credential Access and Lateral Movement are empty looks good on a heatmap and is worthless in an incident. Weight by technique prevalence and impact.
* [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) scores data source quality alongside coverage — more honest than counting rules.

## Pre-ship review checklist

- [ ] **Title** describes the behavior, not the tool; readable in an alert queue
- [ ] Stable `id` (UUIDv4), correct `status`, `author`, `date`
- [ ] ATT&CK `tags` present and correct (tactic + technique + sub-technique)
- [ ] `logsource` matches a log source that is actually deployed and ingested — verified, not assumed
- [ ] Every field name exists in the target schema after pipeline conversion (`sigma convert` output eyeballed against real events)
- [ ] Anchored on a behavioral invariant, not a filename/hash the attacker controls
- [ ] Tested against a **true positive** (Atomic Red Team test number recorded in the rule references)
- [ ] Run against ≥30 days of production history; FP volume measured and within budget
- [ ] `falsepositives` documented in plain language for the triaging analyst
- [ ] Every exclusion justified in a comment and scoped to something the attacker can't set
- [ ] `level` matches the actual response — `critical` means someone gets woken up
- [ ] Runbook exists: what to check, what to ask, when to escalate, how to contain
- [ ] Evasion considered — write down how you'd bypass your own rule, then decide whether to widen it or add a companion rule
- [ ] Performance sane (no unbounded regex over the largest index; no leading wildcards where avoidable)
- [ ] Merged to git with review; deployed via pipeline, not by hand
