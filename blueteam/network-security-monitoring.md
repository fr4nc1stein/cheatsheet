# Network Security Monitoring

NSM is the discipline of collecting and analyzing network data to detect and validate intrusions. Its key property: **it survives host compromise.** An attacker with SYSTEM can clear the event log and kill the EDR agent; they cannot un-send the packets that already crossed your sensor.

Three data types, in increasing cost and decreasing retention:

| Type | Example | Retention | Best for |
| --- | --- | --- | --- |
| **Flow / transaction logs** | Zeek `conn.log`, NetFlow/IPFIX | Months | Scoping, hunting, "who talked to what, when, how much" |
| **Alert data** | Suricata/Snort alerts | Months | Known-bad signature hits |
| **Full packet capture** | PCAP | Days | Proving exactly what was taken; deep analysis of a known event |

Zeek gives you the long tail cheaply; PCAP answers "what exactly was in it" for the few days you keep it. Run both.

## Sensor placement

* **North-south** (perimeter/egress) — catches C2 and exfil. Everyone monitors here. Place the sensor **inside** the NAT boundary so you retain internal source IPs; outside it, every connection appears to come from one address.
* **East-west** (internal/inter-VLAN) — catches lateral movement, internal scanning, SMB abuse. Usually the biggest blind spot in a real network.
* **Datacenter / crown jewels** — DC-to-DC replication, database egress, backup network, hypervisor management.
* **VPN and remote access concentrator egress** — remote users bypass the office perimeter entirely.
* **Cloud** — VPC/VNet flow logs, AWS Traffic Mirroring, Azure vTAP/NSG flow logs, GCP Packet Mirroring.

| | Network TAP | SPAN / mirror port |
| --- | --- | --- |
| Fidelity | Full, passive, fails open | Switch drops frames under load; errors/runts often filtered |
| Cost | Hardware per link | Free (uses a switch port) |
| Risk | None to production traffic | Contends with switching capacity |
| Use | High-value links, DMZ, egress | Everywhere else, and for getting started |

**Practicalities:** monitoring interfaces should have no IP address and be receive-only. Size the sensor for peak, not average. Confirm you actually see both directions of traffic — asymmetric routing silently halves your visibility, and Zeek/Suricata will produce misleading logs rather than errors.

## Zeek

Zeek is not an IDS — it's a **network transaction logger**. It writes structured records for every connection and protocol event, which is what makes retrospective hunting possible.

| Log | Contains | Hunt for |
| --- | --- | --- |
| `conn.log` | 5-tuple, duration, bytes both directions, `conn_state`, history | Beaconing, long connections, large uploads, scanning, first-seen pairs |
| `dns.log` | Query, type, response, rcode, TTL | Tunneling, DGA, NXDOMAIN storms, TXT abuse, newly-seen domains |
| `http.log` | Host, URI, method, User-Agent, status, referrer, MIME | Malicious UAs, odd URI patterns, payload downloads, cleartext credential exposure |
| `ssl.log` | SNI, version, cipher, JA3/JA3S, cert subject/issuer, validation status | Self-signed C2, cert anomalies, SNI mismatch, unusual TLS fingerprints |
| `x509.log` | Full certificate detail | Cert-based pivoting; short-lived and auto-generated certs |
| `files.log` | Files seen on the wire, MIME, hashes, source protocol | Malware transfer, exfil archives; hash lookups against intel |
| `notice.log` | Zeek's own alerts (Intel hits, scan detection, SSL notices) | Triage queue |
| `smb_*.log`, `dce_rpc.log`, `ntlm.log`, `kerberos.log` | Windows protocol detail | **Lateral movement**, admin share access, PsExec, Kerberoasting on the wire |
| `weird.log` | Protocol violations and unexpected behavior | Tunneling, evasion, broken/handcrafted implementations |
| `ssh.log` | Client/server version, auth success inference, HASSH | Unauthorized SSH, brute force, tunneling clients |
| `intel.log` | Hits against loaded intel framework indicators | Direct IOC matching in-line |

**Tools/Commands:**

```
# zeek-cut extracts named fields from a TSV log — the core analysis idiom
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state

# Top talkers by bytes out — exfil candidates
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes \
  | awk '{sum[$1" "$2]+=$3} END {for (k in sum) print sum[k], k}' | sort -rn | head -20

# Long-duration connections (>1h) — persistent C2 / tunnels
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration | awk '$4>3600' | sort -k4 -rn

# Rare User-Agents (stack counting)
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -30

# Self-signed / untrusted certs seen in TLS
cat ssl.log | zeek-cut server_name subject issuer validation_status | grep -v "^-.*ok$" | sort | uniq -c | sort -rn

# JA3 client fingerprints, rarest first
cat ssl.log | zeek-cut ja3 server_name | sort | uniq -c | sort -n | head -30

# DNS: highest-volume queried domains and NXDOMAIN rates per host
cat dns.log | zeek-cut query | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20
cat dns.log | zeek-cut id.orig_h rcode_name | grep NXDOMAIN | cut -f1 | sort | uniq -c | sort -rn

# Files transferred, with hashes, for IOC matching
cat files.log | zeek-cut tx_hosts rx_hosts mime_type filename sha256 | grep -v "^-"

# Process a PCAP offline into logs
zeek -C -r capture.pcap local
zeek -C -r capture.pcap local "Log::default_rotation_interval = 0secs"
```

`conn_state` values worth knowing: `S0` (SYN, no reply — scanning), `REJ` (rejected), `SF` (normal establish+close), `RSTO`/`RSTR` (reset by originator/responder), `OTH` (no SYN seen — mid-stream or asymmetric routing).

Zeek's **Intel framework** ingests indicator files and writes `intel.log` on any match across any protocol — the cheapest way to operationalize an IOC feed at the network layer.

## Suricata / Snort

Signature-based inspection. Where Zeek logs *everything that happened*, Suricata alerts on *things matching a rule*. Both, not either.

**Rule anatomy:**

```
action proto src_ip src_port -> dst_ip dst_port (rule options)
```

```
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"ET TROJAN Generic Loader Checkin URI Pattern"; \
    flow:established,to_server; \
    http.method; content:"POST"; \
    http.uri; content:"/api/v2/checkin.php"; startswith; \
    content:"?id="; distance:0; \
    http.user_agent; content:"MSIE 9.0"; \
    threshold:type limit, track by_src, count 1, seconds 300; \
    reference:url,internal/INC-2026-0412; \
    classtype:trojan-activity; \
    sid:9000117; rev:2; \
    metadata:attack_target Client_Endpoint, created_at 2026_08_11, mitre_technique_id T1071.001; )
```

| Option | Purpose |
| --- | --- |
| `msg` | Alert text the analyst reads — make it specific |
| `flow` | Direction and state — `established,to_server` avoids matching stray packets |
| `content` / `pcre` | Payload match; sticky buffers (`http.uri`, `http.host`, `http.user_agent`, `tls.sni`, `dns.query`, `file.data`) scope the match and are far cheaper than raw `pcre` |
| `nocase`, `startswith`, `endswith`, `depth`, `offset`, `distance`, `within` | Positional constraints — always constrain, unconstrained content matches are expensive |
| `threshold` / `detection_filter` | Rate limiting; essential for noisy conditions |
| `flowbits` | Multi-packet/multi-event state ("saw request, now check response") |
| `sid` / `rev` | Unique ID (use 1,000,000+ for local rules) and revision |
| `classtype`, `reference`, `metadata` | Triage context and ATT&CK mapping |

```
suricata -T -c /etc/suricata/suricata.yaml -S local.rules   # test config + rules before deploying
suricata -r capture.pcap -S local.rules -l ./out/           # offline PCAP replay against rules
suricata-update                                             # pull ET Open / other rule sources
jq -r 'select(.event_type=="alert") | [.timestamp,.src_ip,.dest_ip,.alert.signature] | @tsv' eve.json
```

Suricata also emits Zeek-like protocol records in `eve.json` (`http`, `dns`, `tls`, `flow`, `fileinfo`) — in a small environment it can serve as both IDS and transaction logger. IPS mode (inline, `drop` action) requires confidence in your rules and a plan for what happens when the sensor fails.

**Signature limits:** encrypted traffic defeats payload inspection, and any custom C2 will have no public signature. Signatures catch commodity malware and known exploit traffic; behavioral analysis over Zeek logs catches the rest.

## PCAP analysis at scale

```
# Field extraction — the tshark idiom that replaces GUI clicking
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.host -e http.request.uri \
       -Y "http.request" -E separator=,

# TLS SNI + JA3 (JA3 requires the ja3 dissector/lua or Zeek; SNI is native)
tshark -r capture.pcap -T fields -e ip.dst -e tls.handshake.extensions_server_name -Y "tls.handshake.type == 1" | sort -u

# DNS queries and responses
tshark -r capture.pcap -T fields -e dns.qry.name -e dns.a -Y "dns.flags.response == 1" | sort | uniq -c | sort -rn

# Conversation statistics — top talkers without any manual reading
tshark -r capture.pcap -q -z conv,tcp | head -30
tshark -r capture.pcap -q -z io,phs                    # protocol hierarchy — what's actually in here

# Carve transferred objects
tshark -r capture.pcap --export-objects http,./out/
tshark -r capture.pcap --export-objects smb,./out/
foremost -i capture.pcap -o carved/

# Split a huge capture into workable pieces / filter down first
editcap -c 100000 big.pcap chunk.pcap
tcpdump -r big.pcap -w filtered.pcap 'host 185.220.101.5 or port 4444'

# Follow a single stream
tshark -r capture.pcap -q -z follow,tcp,ascii,42
```

**Workflow:** never open a multi-gigabyte PCAP in Wireshark first. Run it through Zeek, find the connection of interest in `conn.log`, extract that 5-tuple with `tcpdump`/`editcap`, *then* open the small result in Wireshark.

## Encrypted traffic analysis

You can't read the payload. You can read everything around it.

| Signal | What it gives you |
| --- | --- |
| **JA3** | MD5 hash of the TLS **client** hello (version, ciphers, extensions, curves, formats). Fingerprints the client *library*, not the host — Cobalt Strike, Metasploit, Python `requests`, and curl each have known values |
| **JA3S** | Same for the **server** hello. JA3+JA3S as a pair is far more specific than either alone |
| **JA4 / JA4+** | The successor suite (JA4 TLS client, JA4S server, JA4H HTTP, JA4X certs, JA4T TCP). Human-readable, ordering-resilient, and not defeated by the cipher-shuffling that broke JA3's reliability. Prefer JA4 in new deployments; keep JA3 for compatibility with existing intel |
| **HASSH / HASSHServer** | The SSH equivalent — fingerprints SSH client/server implementations |
| **JARM** | Active server-side fingerprint — scan a suspected C2 IP and compare against known C2 framework JARMs |

**Certificate anomalies:** self-signed certs on external destinations; validity periods of exactly 1 year with default Let's Encrypt patterns on brand-new domains; subject fields left at library defaults or filled with random strings; CN not matching the SNI; certs shared across many unrelated IPs (pivot with Censys/Shodan to find the rest of the infrastructure).

**SNI and domain fronting:** SNI that doesn't match the HTTP `Host` inside the tunnel is classic fronting (largely mitigated by CDNs, but ESNI/ECH reintroduces the blind spot). Watch for high-reputation CDN SNIs carrying traffic that beacons. Also: connections to an IP with **no preceding DNS lookup** from that host — hardcoded C2 addresses skip resolution, and this is one of the most reliable encrypted-traffic signals available.

```
# Rare JA3s in the environment — stack counting again
cat ssl.log | zeek-cut ja3 ja3s server_name id.resp_h | sort | uniq -c | sort -n | head -40

# TLS connections with no prior DNS resolution for that destination (conceptual join)
cat ssl.log  | zeek-cut id.resp_h | sort -u > tls_dsts.txt
cat dns.log  | zeek-cut answers | tr ',' '\n' | sort -u > resolved.txt
comm -23 tls_dsts.txt resolved.txt
```

## C2 detection

### Beaconing

Automation is regular; humans are not. Measure interval regularity.

* **Metrics:** coefficient of variation of inter-arrival times (`stdev/mean`), variance of payload size, connection count, total duration of the pattern.
* **Jitter** is the counter — a 20–50% jitter setting widens the distribution. Don't threshold too tightly; look at the *distribution shape* (bimodal, bounded uniform) not just the CV. Real user traffic is bursty and heavy-tailed; jittered beacons are still bounded.
* **Also weight:** small, near-constant payload sizes; a destination contacted by exactly one internal host; a domain registered in the last 30 days; connections continuing outside business hours when the user is offline.
* [**RITA**](https://github.com/activecm/rita) consumes Zeek logs and scores beacons, long connections, DNS tunneling, and strobes directly. It is the fastest way to get this capability without writing the math yourself. [AC-Hunter](https://www.activecountermeasures.com/ac-hunter/) is the commercial version.

```
rita import /opt/zeek/logs/2026-08-10/*.log dataset01
rita show-beacons dataset01 | head -25
rita show-long-connections dataset01 | head -25
rita show-exploded-dns dataset01 | head -25
rita show-strobes dataset01
```

SPL/KQL beacon queries are in [Threat Hunting](threat-hunting.md#5-beaconing-detection-t1071).

### DNS tunneling / DNS C2

| Indicator | Detail |
| --- | --- |
| **Query volume** to a single parent domain | Hundreds to thousands of unique subdomains under one registered domain from one host |
| **Subdomain entropy and length** | Encoded data looks random; legitimate labels don't. Alert on high Shannon entropy + long labels (>40 chars) |
| **Record types** | Heavy `TXT`, `NULL`, `CNAME`, or `A` with unusual patterns; `TXT` in volume is rarely legitimate outside SPF/DKIM lookups |
| **Response size / rate** | Large TXT responses; high query rate with low cache hit behavior |
| **NXDOMAIN rate** | DGA lookups fail constantly; a host with a high NXDOMAIN ratio is either infected or misconfigured |
| **Unique-subdomain-to-parent ratio** | The single best feature: `dc(query) by parent_domain` per host |
| **Bypassing internal resolvers** | Any host talking UDP/TCP 53 or DoH (443 to known DoH providers) directly to the internet — should be blocked outright, and any attempt alerted |

```
# Unique subdomains per registered domain per host
cat dns.log | zeek-cut id.orig_h query \
 | awk '{n=split($2,a,"."); print $1, a[n-1]"."a[n], $2}' \
 | sort -u | awk '{print $1, $2}' | uniq -c | sort -rn | head -20
```

### Other C2 signals

* **Long connections** — a single TCP session open for hours/days to an external host (`duration` in `conn.log`). Legitimate cases exist (VPN, SaaS websockets, RDP), so baseline first.
* **Unusual User-Agents** — missing, malformed, hardcoded old IE strings, PowerShell's default `Mozilla/5.0 (Windows NT; ...) WindowsPowerShell/5.1`, `python-requests`, `curl`, or a UA used by exactly one host in the estate.
* **Protocol/port mismatch** — TLS on 8080, SSH on 443, HTTP on 53, or plain binary on a well-known port. Zeek identifies protocols by content, not port, so `service` vs `id.resp_p` disagreement is directly queryable.
* **New/rare destinations** — first-seen external IP or domain for the org, especially newly-registered domains and known-bad hosting ASNs.
* **Direct-to-IP HTTP/TLS** with no DNS, and connections from server subnets that should never egress at all.

## Data exfiltration indicators

* **Volumetric:** outbound bytes far exceeding inbound on a session; a host's daily upload volume many standard deviations above its own baseline; large transfers outside business hours.
* **Destination:** cloud storage and paste sites not on the approved list (`mega.nz`, `anonfiles`, `transfer.sh`, `pastebin`, personal Google Drive/Dropbox), newly-registered domains, hosting providers with no business relationship.
* **Protocol abuse:** DNS tunneling (above), ICMP with large/odd payloads, HTTP POST bodies far larger than typical, FTP/SFTP/SCP from workstations, WebDAV.
* **Staging first:** on the host, look for large `.7z`/`.rar`/`.zip` archives created in `C:\Users\Public`, `ProgramData`, or `$RECYCLE.BIN` shortly before the upload, and for `rclone`/`WinSCP`/`MegaSync`/`FileZilla` execution ([DFIR](dfir.md)). Correlating the host artifact with the network flow is what turns "large upload" into "confirmed exfil."
* **Slow and low:** rate-limited exfil hides in daily volume. Trend per-host upload over weeks, not per-session.
* **SRUM** on Windows gives per-process bytes-sent — the on-host corroboration for a network finding.

## Baselining

Anomaly detection without a baseline is just alerting on "things I haven't seen", which in a real network means alerting constantly.

**Establish and maintain:**

- [ ] **Normal egress destinations** per network segment — which subnets should talk to the internet at all? Server VLANs usually shouldn't
- [ ] **Protocol/port profile** per segment, with an explicit list of what is allowed
- [ ] **Typical volume** per host and per segment, by hour of day and day of week
- [ ] **Known-good beacons** — telemetry agents, AV updaters, monitoring, NTP, SaaS keepalives. Allowlist by destination, and review when vendors change
- [ ] **Approved User-Agents and JA3/JA4 fingerprints** for managed software
- [ ] **East-west norms** — which hosts should ever initiate SMB/WinRM/RDP to which? Everything else is a lateral movement candidate
- [ ] **Asset inventory joined to network data** — an IP with no owner is a finding in its own right

Re-baseline after major changes (new SaaS rollout, VPN migration, cloud move). A stale baseline generates the same fatigue as an untuned rule.
