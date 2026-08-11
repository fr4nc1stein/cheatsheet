# DFIR — Digital Forensics & Incident Response

## Incident response lifecycle

NIST SP 800-61r2 (four phases; SANS splits into six — same work, different boxes):

| NIST phase | SANS phases | What actually happens |
| --- | --- | --- |
| Preparation | Preparation | IR plan, comms tree, retainers, tooling deployed, logging validated, tabletop exercises, known-good baselines |
| Detection & Analysis | Identification | Triage the alert, confirm true positive, scope the blast radius, build an initial timeline |
| Containment, Eradication & Recovery | Containment / Eradication / Recovery | Isolate, remove attacker access and artifacts, rebuild, restore, monitor for return |
| Post-Incident Activity | Lessons Learned | Report, root cause, control gaps, new detections, action items with owners and dates |

**The loop that matters:** analysis → containment → *more* analysis. Scoping is never finished on the first pass; every new host found restarts the cycle.

## Order of volatility

Collect most-volatile first (RFC 3227):

1. CPU registers, cache
2. **Memory (RAM)** — running processes, injected code, decrypted payloads, network state, credentials, encryption keys
3. Network state — active connections, ARP cache, routing table, listening ports
4. Running processes, loaded modules, open handles
5. Temporary filesystem / swap / pagefile / hiberfil
6. Disk — filesystem metadata, then file content
7. Remote logs and monitoring data (SIEM, EDR cloud, netflow)
8. Physical/topology config and archival media

**Practical:** if the host is powered on and you have any doubt, **capture memory before you do anything else** — including before running triage collection, which itself changes memory. Pulling the plug on a suspected ransomware host destroys the key material that may be sitting in RAM.

## Evidence handling and chain of custody

**Checklist:**

- [ ] Record who collected, what, from where, when (with timezone — use UTC everywhere), and with which tool/version
- [ ] Hash every acquired image/artifact at acquisition (`sha256sum`) and record it; re-verify after transfer
- [ ] Use write blockers (hardware or software) for physical disk acquisition
- [ ] Work on **copies**; keep the original image read-only and untouched
- [ ] Log every custody transfer — person to person, signed and timestamped
- [ ] Store in an access-controlled location; document retention and destruction
- [ ] Assume every artifact may end up in litigation, regulatory filing, or insurance claim — document as if it will

```
sha256sum evidence.E01 | tee evidence.E01.sha256
ewfverify evidence.E01                     # verify EWF/E01 integrity
```

## Triage collection

Full disk images do not scale in a multi-host incident. Collect targeted artifacts first, image only what matters.

| Tool | Platform | Notes |
| --- | --- | --- |
| [KAPE](https://www.kroll.com/kape) | Windows | Targets (collect) + Modules (parse). `!SANS_Triage` target is the standard starting set |
| [Velociraptor](https://docs.velociraptor.app/) | Win/Lin/mac | Fleet-scale: VQL hunts across thousands of endpoints, live or triage; the best free option for scoping |
| [CyLR](https://github.com/orlikoski/CyLR) | Win/Lin/mac | Single small binary, fast raw-filesystem artifact collection, no dependencies |
| [UAC](https://github.com/tclahr/uac) | Linux/Unix/macOS | Shell-only live response collector for *nix |
| [FastIR](https://github.com/SekoiaLab/Fastir_Collector) / DFIR ORC | Windows | Alternatives where KAPE licensing is a problem |

```
# KAPE: collect SANS triage set, then parse with all modules to CSV
kape.exe --tsource C: --tdest E:\triage\%m --target !SANS_Triage --vss
kape.exe --msource E:\triage\HOST --mdest E:\parsed\HOST --module !EZParser --mef csv

# CyLR: collect to a zip, ship over SFTP
CyLR.exe -od E:\out -of HOST.zip

# Velociraptor: offline collector, or a server-side hunt across the fleet
velociraptor collector -- config client.config.yaml
# VQL hunt: find processes with a given binary across all endpoints
SELECT * FROM pslist() WHERE Name =~ "(?i)rundll32"
```

## Live response vs. dead-box

| | Live response | Dead-box |
| --- | --- | --- |
| Gets you | Memory, running processes, network state, decrypted data, fast answers | Deleted files, slack space, full filesystem timeline, defensible integrity |
| Costs you | Modifies the system; a rootkit may lie to you | Downtime; loses all volatile state |
| Use when | Scoping is active, host must stay up, you need answers in hours | Single high-value host, legal/HR matter, or the malware is anti-analysis heavy |

In practice: **memory capture → triage collection → decide whether a full image is warranted.** Most enterprise incidents never need a full image.

## Memory acquisition and analysis

| Tool | Platform |
| --- | --- |
| [WinPMem](https://github.com/Velocidex/WinPmem) | Windows — free, signed driver, outputs raw/AFF4 |
| [DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) (Magnet) | Windows — single-click raw dump |
| [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) / FTK Imager | Windows — GUI options |
| [AVML](https://github.com/microsoft/avml) | Linux — portable, no target-kernel build needed |
| [LiME](https://github.com/504ensicsLabs/LiME) | Linux — LKM, requires matching kernel headers |
| `vmss2core` / VMware `.vmem` | Virtual machines — snapshot the VM and take the `.vmem`, zero footprint on the guest |

```
winpmem_mini_x64_rc2.exe E:\mem\HOST.raw
avml /mnt/evidence/host-mem.lime
# Virtual machines: suspend the VM and copy the .vmem file — cleanest possible acquisition
```

**Analysis** is [Volatility 3](https://github.com/volatilityfoundation/volatility3); plugin-by-plugin usage is already covered in [CTF Forensics & Steganography](../ctf/forensics-and-steganography.md) — the same commands apply. IR-specific priorities:

* `windows.pstree` / `windows.psscan` — process lineage and hidden/unlinked processes
* `windows.cmdline` — full command lines, including ones never written to disk
* `windows.malfind` — RWX private memory with no backing file = injected code
* `windows.netscan` — connections and owning PIDs, including closed ones
* `windows.dlllist` / `windows.handles` — unbacked modules, suspicious named pipes/mutexes
* `windows.svcscan`, `windows.registry.printkey` — persistence
* `windows.vadyarascan --yara-file rules.yar` — run your [YARA](malware-analysis.md) rules against process memory; the single highest-yield step when you already know what family you're chasing
* [MemProcFS](https://github.com/ufrisk/MemProcFS) mounts a dump as a filesystem — much faster for interactive exploration

## Key Windows artifacts

| Artifact | Location | What it proves |
| --- | --- | --- |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Program **executed** — name, path, run count, last 8 run times, files/dirs referenced at load. Disabled by default on servers/SSD-tuned images |
| **Amcache.hve** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program presence — full path, SHA1, PE compile time, publisher. Presence ≠ execution, but excellent for "was this binary ever here" |
| **ShimCache** (AppCompatCache) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Path, size, and last-modified of binaries the system *considered*; ordered by recency. **Execution is not guaranteed**; flushed to registry on shutdown |
| **SRUM** | `C:\Windows\System32\SRU\SRUDB.dat` | Per-process **network bytes sent/received** and per-user app usage over ~30–60 days — the best on-host exfiltration evidence |
| **$MFT** | Volume root `$MFT` | Every file's MACB timestamps, size, resident content for tiny files; deleted-file records. Foundation of the timeline |
| **$UsnJrnl:$J** | Volume root `$Extend\$UsnJrnl` | File create/rename/delete/write events with reasons — recovers filenames of files already deleted and wiped |
| **$LogFile** | Volume root `$LogFile` | NTFS transaction log; fine-grained recent metadata changes |
| **Event Logs** | `C:\Windows\System32\winevt\Logs\*.evtx` | Auth, process creation, services, PowerShell, RDP. See [SIEM & Log Analysis](siem-and-log-analysis.md) |
| **Registry hives** | `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat` | Persistence (Run keys, services, tasks), USB history, network profiles, typed paths, MRU lists |
| **ShellBags** | `UsrClass.dat` (`BagMRU`) | Folders a user **browsed** — including deleted, external, and network folders |
| **Jump Lists / LNK** | `%AppData%\Microsoft\Windows\Recent\` | File opened by a user, original path, volume serial — proves access to files no longer present |
| **RecentDocs / OpenSaveMRU** | `NTUSER.DAT` | User file interaction history |
| **WMI repository** | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` | WMI event subscription persistence (T1546.003) |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks\` (XML) + 4698 | Persistence, with author and action |
| **Browser history/cache** | Per-browser profile dirs | Initial access via download/phish, exfil to webmail/cloud storage |
| **RDP artifacts** | `bam`/`dam`, `Default.rdp`, 4624 Type 10, TerminalServices-* logs | Interactive remote access, source IP, and the user |

**Parsers (Eric Zimmerman's tools + others):**

```
PECmd.exe -d C:\triage\Prefetch --csv out\            # Prefetch
AmcacheParser.exe -f Amcache.hve --csv out\
AppCompatCacheParser.exe -f SYSTEM --csv out\
MFTECmd.exe -f $MFT --csv out\                        # also parses $J, $Boot, $SDS
SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv out\
RECmd.exe -d C:\triage\Registry --bn BatchExamples\Kroll_Batch.reb --csv out\
LECmd.exe -d "C:\triage\Recent" --csv out\            # LNK
JLECmd.exe -d "C:\triage\AutomaticDestinations" --csv out\
EvtxECmd.exe -d C:\triage\winevt\Logs --csv out\
hayabusa csv-timeline -d C:\triage\winevt\Logs -o hayabusa.csv   # Sigma-backed EVTX triage
regripper -r NTUSER.DAT -f ntuser                     # alternative registry parsing
```

Review CSV output in [Timeline Explorer](https://ericzimmerman.github.io/) — it handles million-row files and lets you stack/filter fast.

## Super timeline

One chronological view across every artifact type — the single most effective technique for reconstructing an intrusion.

```
# Build (from a mounted image, triage folder, or E01)
log2timeline.py --storage-file case.plaso /mnt/evidence/

# Filter to a window and export to CSV
psort.py -o l2tcsv -w timeline.csv case.plaso \
  "date > '2026-07-01 00:00:00' AND date < '2026-07-15 00:00:00'"

# Lightweight alternative: filesystem-only timeline from $MFT
MFTECmd.exe -f $MFT --csvf mft.csv --csv out\
```

**Analysis workflow:** find a **pivot** (first known-bad timestamp — the alert, the malicious file's creation, the suspicious logon), then read ±30 minutes in full. Intrusions are dense: the dropper, the persistence, the discovery commands, and the first lateral hop usually sit within one screen of each other. Then move to the next pivot. Load into Timeline Explorer or [Timesketch](https://timesketch.org/) for collaborative tagging.

**Timestamp cautions:** normalize everything to UTC. `$MFT` `$STANDARD_INFORMATION` timestamps are trivially forgeable (timestomping, T1070.006); `$FILE_NAME` timestamps are not directly settable via the Win32 API — a `$SI` earlier than `$FN` is a timestomping indicator.

## Linux IR artifacts

| Artifact | Location | Value |
| --- | --- | --- |
| Auth logs | `/var/log/auth.log`, `/var/log/secure` | SSH logons, `sudo`, user/group changes |
| Shell history | `~/.bash_history`, `~/.zsh_history` | Attacker commands (no timestamps unless `HISTTIMEFORMAT` set; trivially cleared) |
| Cron / systemd timers | `/etc/cron*`, `/var/spool/cron/`, `/etc/systemd/system/*.timer` | Persistence |
| Systemd services | `/etc/systemd/system/`, `/lib/systemd/system/` | Persistence, malicious daemons |
| SSH keys | `~/.ssh/authorized_keys` | Attacker-added persistent access — check mtime |
| Preload hijack | `/etc/ld.so.preload`, `LD_PRELOAD` | Userland rootkit |
| Web shells | Web root — files with recent mtime, odd owner | Initial access on exposed servers |
| Utmp/wtmp/btmp | `/var/log/wtmp`, `btmp`, `lastlog` | Logon sessions (`last`, `lastb`) |
| Audit logs | `/var/log/audit/audit.log` (auditd) | Syscall-level execution evidence, if auditd was configured |
| Package/timeline | `rpm -Va`, `debsums -c` | Modified system binaries |

```
find / -xdev -newermt "2026-07-01" -type f -printf "%T+ %u %p\n" 2>/dev/null | sort
last -Faixw ; lastb -F | head -50
systemctl list-units --type=service --state=running
ls -la /proc/*/exe 2>/dev/null | grep -i deleted     # running binary deleted from disk
ss -antp | grep ESTAB
stat /etc/passwd /etc/shadow ~/.ssh/authorized_keys
```

## Containment decisions

Isolating early stops the damage but burns your visibility — the attacker learns they're detected and may accelerate to destruction or go quiet and return via a channel you haven't found.

| Contain immediately when | Delay containment when |
| --- | --- |
| Ransomware staging or encryption has started | Scope is unknown and only one host is confirmed |
| Active exfiltration of regulated data | You have strong EDR visibility and can watch safely |
| Domain admin / DC / CA compromise confirmed | Isolating tips off the attacker before you've found all persistence |
| Destructive tooling observed (wipers, `vssadmin delete shadows`) | Legal/leadership wants evidence of scope first |

**Rules of thumb:**

* **Contain everything at once, not host by host.** Sequential isolation is how you end up chasing an attacker across the estate for three weeks.
* Prefer **network isolation** (EDR host-isolation, VLAN quarantine, switch port) over powering off — you keep memory and the ability to investigate.
* If DA or the KRBTGT account is suspected compromised: reset KRBTGT **twice**, with a gap longer than the maximum ticket lifetime (10h default) between resets, and rotate the DSRM password, AD CS keys, and all service accounts.
* Block egress before you rebuild — otherwise the restored host reconnects to C2 from the same backdoored image.

## Ransomware-specific IR

- [ ] **Do not power off** encrypting hosts — keys may be in memory. Isolate at the network instead, then acquire RAM.
- [ ] Identify the family/variant ([ID Ransomware](https://id-ransomware.malwarehunterteam.com/), [No More Ransom](https://www.nomoreransom.org/)) — a free decryptor may exist; some variants have flawed crypto.
- [ ] Assume **data theft preceded encryption** — nearly all modern crews exfiltrate first. Hunt for staging archives (`.7z`/`.rar` in `C:\Users\Public`, `ProgramData`, `$RECYCLE.BIN`) and large uploads to `mega.nz`, `rclone`, `MegaSync`, `FileZilla`, `WinSCP`, AnyDesk/Rclone-over-SFTP. Check SRUM for per-process bytes-sent.
- [ ] Verify backups **offline and immutable** before restoring; attackers delete/encrypt backups first. Check for `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`, backup-server logons.
- [ ] Find the **initial access vector** before restoring, or you will be re-encrypted: exposed RDP, VPN with no MFA, edge-device CVE, phishing, compromised MSP.
- [ ] Rotate every credential that touched the environment; assume full domain compromise if a DC was encrypted.
- [ ] Engage legal/insurance/regulator early — notification clocks (GDPR 72h, sector rules) start at awareness. Ransom payment decisions are a business/legal call, not an analyst call, and may carry sanctions exposure.
- [ ] Preserve the ransom note, the encrypted-file samples, and the attacker's contact/portal details — they aid family ID and law-enforcement referral.

## Incident report contents

- [ ] **Executive summary** — what happened, impact, current status, in plain language, no jargon
- [ ] **Timeline** in UTC — from first attacker activity (not first alert) to containment
- [ ] **Initial access vector** and root cause — the control that failed
- [ ] **Scope** — accounts, hosts, data confirmed accessed/exfiltrated, and explicitly what was *ruled out* and how
- [ ] **Attacker TTPs** mapped to ATT&CK technique IDs
- [ ] **IOCs** — hashes, IPs, domains, filenames, accounts, in a table that can be fed to tooling
- [ ] **Response actions taken**, with times
- [ ] **Evidence inventory** and chain of custody references
- [ ] **Gaps** — telemetry that was missing, detections that should have fired and didn't
- [ ] **Remediation actions** with named owners and due dates, split short-term / strategic
- [ ] **Detections created** as a result — link them; an incident that produces no new rule was not fully closed
