# Threat Intelligence

Intel is only useful if it changes a decision — a block, a hunt, a detection, a control. Feeds you ingest but never act on are noise with a subscription fee.

## IOCs vs TTPs

| | Indicator of Compromise (IOC) | Tactic, Technique, Procedure (TTP) |
| --- | --- | --- |
| Example | `185.220.101.5`, `a3f1...` SHA256, `evil-cdn.top` | "Dumps LSASS with a renamed `procdump.exe`" |
| Lifetime | Hours to weeks | Months to years |
| Cost to adversary to change | Trivial | High — requires retooling or retraining |
| Detection built on it | Exact match, brittle | Behavioral, durable |
| Best use | Retro-hunting, blocking, scoping an incident | Detection engineering, hunting |

IOCs are for *scoping and blocking what you already know*. TTPs are for *catching what you don't*. Both matter; only one scales.

## Pyramid of Pain

David Bianco's model — the higher up you detect, the more it costs the adversary to adapt.

| Level | Indicator | Pain to adversary | Notes |
| --- | --- | --- | --- |
| 6 (top) | **TTPs** | Tough | Changing behavior means retraining operators or rewriting tradecraft |
| 5 | **Tools** | Challenging | Forces them to find/build a new tool (e.g. you detect Mimikatz generically, not by hash) |
| 4 | **Network/Host Artifacts** | Annoying | Distinctive URI patterns, mutex names, User-Agents, registry keys, named pipes |
| 3 | **Domain Names** | Simple | Costs money and registration time, but cheap at scale |
| 2 | **IP Addresses** | Easy | New VPS in minutes |
| 1 (bottom) | **Hash Values** | Trivial | Change one byte, new hash |

**Practical read:** hash and IP blocklists are hygiene, not a program. Budget your detection engineering time at levels 4–6.

## Diamond Model

Every intrusion event has four vertices connected by edges:

* **Adversary** — the operator/organization.
* **Capability** — malware, exploit, tooling, technique.
* **Infrastructure** — C2 servers, domains, redirectors, email accounts, VPS providers.
* **Victim** — the targeted org, person, asset, or data.

The value is **pivoting**: from one known vertex, expand to the others. A malicious domain (infrastructure) resolves to an IP that hosts three other domains (more infrastructure), one of which serves a sample (capability) that shares a mutex with a family you've seen before (adversary link). Meta-features worth recording: timestamp, phase, result, direction, methodology, resources.

## MITRE ATT&CK

The shared language for describing adversary behavior.

* **Tactic** — the adversary's goal for that step. `TA0006 Credential Access`.
* **Technique** — how they achieve it. `T1003 OS Credential Dumping`.
* **Sub-technique** — the specific variant. `T1003.001 LSASS Memory`.
* **Procedure** — the concrete implementation an actor uses (`comsvcs.dll MiniDump` via rundll32).

Matrices: Enterprise (Windows/Linux/macOS/Cloud/Containers/Network), Mobile, ICS.

**Enterprise tactics, in rough order:**

| ID | Tactic | ID | Tactic |
| --- | --- | --- | --- |
| TA0043 | Reconnaissance | TA0005 | Defense Evasion |
| TA0042 | Resource Development | TA0006 | Credential Access |
| TA0001 | Initial Access | TA0007 | Discovery |
| TA0002 | Execution | TA0008 | Lateral Movement |
| TA0003 | Persistence | TA0009 | Collection |
| TA0004 | Privilege Escalation | TA0011 | Command and Control |
| | | TA0010 | Exfiltration |
| | | TA0040 | Impact |

**Tools/Commands:**

* [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — build layers (JSON) scoring techniques by detection coverage, then diff layers over time or overlay a threat actor's known techniques against your coverage to find gaps.
* Practical layer scheme: 0 = no visibility, 1 = telemetry exists but no detection, 2 = detection exists untested, 3 = detection validated by purple team. See [Purple Team & Hardening](purple-team-and-hardening.md).
* Every detection rule should carry its ATT&CK technique ID in metadata — that's what makes coverage measurable.

## Intelligence lifecycle

1. **Direction** — define requirements (PIRs). "Which ransomware crews target our sector and what initial access do they use?" not "send me all the IOCs."
2. **Collection** — feeds, ISAC/ISAO sharing, vendor reporting, internal incident data (often your best source), OSINT, dark web monitoring.
3. **Processing** — normalize, deduplicate, translate, parse into STIX objects or your platform's schema.
4. **Analysis** — turn data into assessment. Apply confidence levels and analytic standards; state what you don't know.
5. **Dissemination** — deliver in the format the consumer can act on (see below).
6. **Feedback** — did it change a decision? Feed that back into direction.

## Strategic vs operational vs tactical

| Type | Audience | Time horizon | Product |
| --- | --- | --- | --- |
| **Strategic** | Execs, CISO, risk | Months–years | Sector threat landscape, actor motivations, risk briefings — drives budget and program direction |
| **Operational** | IR leads, hunt team, SOC management | Weeks–months | Campaign reporting, actor TTP profiles, tooling changes — drives hunts and detection priorities |
| **Tactical** | SOC analysts, detection engineers, tooling | Hours–days | IOCs, Sigma/YARA rules, hashes, C2 infrastructure — drives blocks and alerts |

## Platforms and standards

| Tool / standard | Use |
| --- | --- |
| [MISP](https://www.misp-project.org/) | Open-source intel sharing; events, attributes, galaxies, taxonomies; feeds out to SIEM/firewall |
| [OpenCTI](https://filigran.io/solutions/open-cti/) | Knowledge graph over STIX 2.1 — good for relationships (actor → malware → infrastructure) |
| **STIX 2.1** | The data model for intel objects (indicator, malware, threat-actor, relationship) |
| **TAXII 2.1** | The transport protocol for exchanging STIX collections |
| [Yeti](https://yeti-platform.io/) | Lighter-weight intel repository with observable pivoting |
| Feeds | Abuse.ch ([URLhaus](https://urlhaus.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), [MalwareBazaar](https://bazaar.abuse.ch/)), CISA [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), Spamhaus, commercial vendors |

**Feed hygiene:** score sources on precision. A feed that generates 200 alerts/day of which 2 are real is a detection you should retire, not tune around. Track false-positive rate per source.

## Enrichment workflow

Given an observable, work outward before you escalate:

| Service | Best for |
| --- | --- |
| [VirusTotal](https://www.virustotal.com/) | Hash/URL/domain reputation, sample relationships, behavior reports, retro-hunt with YARA (paid) |
| [urlscan.io](https://urlscan.io/) | Detonating a URL safely; page DOM, redirect chain, screenshots, related scans |
| [Shodan](https://www.shodan.io/) / [Censys](https://search.censys.io/) | What is that IP actually running? Cert and JARM/JA4S pivots to find sibling C2 servers |
| [AbuseIPDB](https://www.abuseipdb.com/) | Crowd-sourced IP abuse reports and categories |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) / [Joe Sandbox](https://www.joesandbox.com/) | Free-tier detonation reports |
| [crt.sh](https://crt.sh/) | Certificate transparency — find sibling/typosquat domains for a registrant |
| [ViewDNS](https://viewdns.info/) / passive DNS (RiskIQ, SecurityTrails) | Historical resolution, reverse IP, shared hosting context |

**Tools/Commands:**

```
# Bulk hash reputation via VT API
curl -s -H "x-apikey: $VT_API_KEY" \
  "https://www.virustotal.com/api/v3/files/$SHA256" | jq '.data.attributes.last_analysis_stats'

# Passive DNS / current resolution and history pivot
dig +short evil-cdn.top
whois 185.220.101.5 | grep -iE "orgname|netname|country"

# Certificate transparency pivot for lookalike domains
curl -s "https://crt.sh/?q=%25yourcompany%25&output=json" | jq -r '.[].name_value' | sort -u
```

**Cautions:**

* **Do not upload client/sensitive samples to public VirusTotal** — the sample becomes available to paying subscribers, including your adversary. Hash-only lookups first; detonate internally.
* Searching a rare hash or C2 domain on a public service can tip off the operator, who may be monitoring for it. During an active intrusion, prefer passive sources.

## A frank note on attribution

Attribution is expensive, slow, frequently wrong, and almost never changes what you do next. Nation-state naming is a job for intelligence agencies and vendors with global telemetry; you have logs from one network.

* **Actionable:** "this activity matches the TTPs of a ransomware affiliate that typically enters via exposed RDP and deploys within 48 hours" → check RDP exposure now, hunt for the staging tooling now.
* **Not actionable:** "this was APT-Whatever." Same containment, same eradication, same hardening.
* Actor names are marketing-adjacent and not interoperable across vendors — the same cluster has five names. Track **TTPs and infrastructure**, use actor names only as a shorthand label for a behavior set.
* Flags in code, timezone in timestamps, and language artifacts are trivially falsifiable and have been faked deliberately. Treat as weak signals at best.

Use intel to prioritize. Do not use it to name a villain.
