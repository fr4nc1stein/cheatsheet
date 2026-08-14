# Getting Started

General approach and tooling for CTF challenges, organized by category. Unlike a pentest engagement, CTF challenges are usually self-contained (a file, a binary, a URL) and the goal is a flag, not persistence — so the workflow is more "identify → analyze → exploit/decode → extract flag."

**The single most important habit:** don't let the category tab a challenge lives under convince you it only uses one skill. A "Forensics" challenge that hands you an image is very often a *delivery mechanism* for a crypto puzzle or a set of web credentials. Read this page before you get tunnel vision on the first tool that gives you a result.

**Category cheatsheets:**

* [Web Exploitation](web-exploitation.md)
* [Binary Exploitation (Pwn)](binary-exploitation.md)
* [Reverse Engineering](reverse-engineering.md)
* [Cryptography](cryptography.md)
* [Forensics & Steganography](forensics-and-steganography.md)
* [OSINT & Misc](osint-and-misc.md)
* [AI & Prompt Injection](ai-and-prompt-injection.md)

## The author's mindset (why chains happen)

Challenge authors don't usually build "one trick, one flag." They build a **delivery layer** (a file format, a network service, a chat UI) wrapped around one or more **puzzle layers** (encoding, encryption, a vulnerability, a logic bug), and the category label on the scoreboard just reflects whichever skill is scored as "primary." Keeping this in mind changes how you read a challenge:

* **Layering is cheap and popular.** Base64 → gzip → XOR → a password-protected zip → a second flag-shaped string that's actually a private key is a completely normal chain. Each layer alone is trivial; the difficulty is recognizing when you've *actually* reached the bottom versus produced another wrapper.
* **Categories describe the last mile, not the whole path.** A "Web" challenge might require you to first decode a cookie value using a technique from Cryptography, or a "Crypto" challenge might ship a `.pcap` that you need Forensics skills to open before you even see the ciphertext.
* **Red herrings are intentional.** Decoy files, plausible-but-wrong flag-format strings, oversized binaries with 99% irrelevant code, and suspiciously named files (`totally_not_the_flag.txt`) exist to burn your time — verify, don't assume.
* **Infrastructure gets reused within an event.** The same Docker base image, the same wordlist, the same "leaked" credential, or the same author quirk (variable names, comment style, a signature XOR key) can show up across multiple challenges in one CTF. If you've solved one challenge from an author/track, revisit its artifacts when stuck on another.
* **Points are a difficulty signal, not a category confirmation.** A 500-point "Misc" challenge that seems to yield to a one-line `strings` command almost certainly isn't done yet.

## How to spot a multi-stage / chained challenge

Treat these as yellow flags — none is proof on its own, but two or more together means stop and assume there's a next step:

* **A decode/extract step produces something that "looks like" input for a *different* domain** — a JSON blob with an RSA modulus inside a forensics dump, a URL or set of credentials embedded in a decompiled binary, a private key sitting in a memory image.
* **What you found doesn't match the flag format.** If the scoreboard expects `flag{...}` and you've extracted something else structured (a password, a key, a base64 blob, a filename) — that's an intermediate artifact, not the answer.
* **`file`/magic-byte identification is ambiguous or the extension lies.** A file that doesn't cleanly resolve to one known type is usually multiple layers stacked, not one exotic stego trick.
* **The challenge ships both a file *and* a live service/URL.** That's a near-guarantee of a two-category chain (e.g., extract a cred from the file, use it against the service).
* **The description reads oddly literal or punny.** Flavor text is a common hint vector — "Bob hid a secret in a picture, but you'll need to talk to my server to get it" is telling you the category tag (say, Forensics) is only step one.
* **Entropy is high but the file "looks" like plaintext or a known format** (or vice versa) — a sign of an extra encryption/compression layer under or over the visible structure. Check with `binwalk -E file` or `ent file`; near-8.0 bits/byte entropy in a region that "should" be text means something's still encoded.
* **A networked binary (pwn) needs a detail you don't have** — the wrong libc version, an unexplained offset, a magic constant — that detail is often sitting in a separate recon/OSINT/forensics artifact from the same challenge set.
* **Multiple files are given together.** Check whether they're independent or halves of one puzzle: split keys, XOR pads, stereo-channel-separated audio, or images meant to be diffed/stacked/XORed against each other.

## Universal triage workflow ("peel the onion")

Run this on *every* new file or artifact you touch, including ones you've already partially processed — re-run it after each decode, because the next layer is a "new" file to triage.

1. **Identify the real type — don't trust the extension.**

```
file <filename>
```

2. **Look for embedded strings / flag-format hints.**

```
strings -n 8 <filename> | grep -iE "flag|ctf|key|pass|http|ssh|BEGIN"
```

3. **Check metadata** — comments, GPS, author fields, and software versions are all free hints.

```
exiftool <filename>
```

4. **Check entropy** to distinguish "encoded" from "encrypted/compressed" from "plaintext" before picking a tool:

```
binwalk -E <filename>        # entropy graph
ent <filename>                # single entropy figure, ~8.0 = high
```

5. **Look for embedded/appended data** — the classic trick is a valid file with something else appended after its logical end (e.g. a ZIP appended after a PNG's `IEND` chunk).

```
binwalk <filename>
binwalk -e <filename>         # extract anything found
```

6. **Diff against a known-good reference** if one is available (an unmodified "before" copy), byte for byte:

```
cmp -l file1 file2
```

7. **Hash it** — sometimes the flag *is* a hash, or the challenge reuses a known file (check the hash on VirusTotal / a hash-lookup site).

```
sha256sum <filename>
```

8. **Keep a chain log.** Write down, in order, every transformation you've undone (`base64 → gunzip → XOR key 0x2a → zip, password "rockyou hit: dragon2000"`). Three or four layers deep it's easy to lose track of what you've already tried, and a clean log lets you retrace or hand the state to a teammate.

## Cross-category decision guide: "I have an unknown blob, now what?"

This is the "file" case generalized — the same tree applies whether it arrived as an attachment, fell out of a pcap, or got decoded from a previous layer.

| `file` output / entropy | Likely next move | Category to read |
| --- | --- | --- |
| Known image/audio/video, low-ish entropy, looks visually/audibly normal | Steganography (LSB, spectrogram, metadata, appended data) | [Forensics & Steganography](forensics-and-steganography.md) |
| Archive/container (`zip`, `7z`, `rar`, `pdf`, Office) | Extraction — check for a password first, then embedded objects/macros | [Forensics & Steganography](forensics-and-steganography.md) |
| ELF/PE/Mach-O, no network service given | Static/dynamic analysis of the binary itself | [Reverse Engineering](reverse-engineering.md) |
| ELF/PE + a `nc host port` in the prompt | Exploit the running service, not just read it | [Binary Exploitation](binary-exploitation.md) |
| High entropy, `file` says generic "data" | Encrypted or compressed — look for a cipher/algorithm hint before brute-forcing | [Cryptography](cryptography.md) |
| Readable text with an unusual but limited character set | Classical cipher or an esoteric encoding, not modern crypto | [Cryptography](cryptography.md), [OSINT & Misc § Encoding identification](osint-and-misc.md#encoding-identification) |
| Short ASCII string with `==`, `%`, `\x`, or all-hex characters | Encoding (base64/URL/hex), reversible without a key | [OSINT & Misc § Encoding identification](osint-and-misc.md#encoding-identification) |
| Disk image (`.dd`, `.img`, `.e01`) or `memdump.raw` | Disk/memory forensics | [Forensics & Steganography](forensics-and-steganography.md) |
| `.pcap`/`.pcapng` | Network forensics — reconstruct streams before assuming crypto | [Forensics & Steganography](forensics-and-steganography.md) |
| A URL only, no files | Web exploitation recon | [Web Exploitation](web-exploitation.md) |
| A chat/prompt interface | Prompt injection, not a "find the bug" challenge | [AI & Prompt Injection](ai-and-prompt-injection.md) |
| Coordinates, a photo of a real place, a username, a social post | OSINT, not a file-format trick | [OSINT & Misc](osint-and-misc.md) |

If a row doesn't cleanly match — for instance `file` says "data" *and* entropy is low-to-medium — that's usually a custom/obfuscated format or a container `binwalk` didn't recognize. Open it in a hex editor and look for repeating structure (fixed-width records, a recognizable header you can Google) before assuming it's encrypted.

## Category playbook: sub-types and chain signals

Each cheatsheet linked below covers the tools in depth. This section is the "how to *think* about it" layer — what sub-types exist inside a category, the signal that tells you which one you're facing, and what it commonly hands off to next.

### Files, Forensics & Steganography

Not one challenge type — at least four, and they need different tools:

* **Media steganography** (data hidden *inside* a valid image/audio/video that still renders/plays normally). Signal: the file opens fine, looks unremarkable, but the challenge emphasizes "look closer" / "listen carefully." → LSB analysis, spectrograms, palette tricks. Often hands off a password, a key, or a second file.
* **Appended/embedded data** (a valid file with extra bytes tacked on after its logical end, or another file's magic bytes buried mid-stream). Signal: file size is larger than the visible content should require; `binwalk` finds a second signature. → extraction chains into whatever the embedded file is (could be any other category from here).
* **Corrupted/malformed file repair** (a valid format with a deliberately broken header — wrong dimensions, wrong CRC, wrong magic bytes). Signal: the file *almost* opens but a viewer errors out or the image is truncated/garbled. → hex-edit the header field back to something valid (e.g. fix a PNG height field to reveal cropped content, fix a zip's local-header CRC).
* **Archive/container extraction** (zip/7z/rar/pdf/Office/disk image acting purely as a wrapper). Signal: `file` cleanly identifies a container format. → password cracking (`zip2john`/`fcrackzip`), macro extraction (`oletools`), or plain unzip if it's not protected. What's inside can be literally anything — treat it as a fresh unknown blob and re-triage.
* **Memory/disk/network forensics** (large structured artifacts — `memdump.raw`, `.dd`, `.pcap`). Signal: file size is large (MBs–GBs) and clearly not a "single asset." → these almost always chain: a pcap yields a transferred file, a memdump yields a process's decrypted secret, a disk image yields a deleted file that's the real challenge.

See [Forensics & Steganography](forensics-and-steganography.md) for tool-by-tool commands, including memory forensics (`Volatility 3`), disk forensics (`Sleuth Kit`/`autopsy`), pcap reconstruction (Wireshark/`tshark`), and blockchain tracing.

### Cryptography

The first fork in the road is **encoding vs. encryption** — mixing these up wastes the most time:

* **Encoding** (base64, hex, URL-encoding, Base32/58/85, Morse, binary) is reversible with *no key*. Signal: a limited/regular character set, predictable padding (`=`), or a length that's a clean multiple of a known encoding's block size. → decode and re-triage the result as a brand-new unknown blob; encodings are almost always a wrapper, not the puzzle itself.
* **Classical ciphers** (Caesar, Vigenère, substitution, rail fence) need a *key or period* but no computational attack. Signal: readable-ish text, wrong-looking letter frequency, a title/description hint pointing at "ancient," "shift," or a specific historical cipher name. → [dCode](https://www.dcode.fr/) or frequency analysis.
* **Modern crypto misuse** (RSA, AES, hashing, PRNGs) is a puzzle about a math/implementation weakness, not about "cracking" in the brute-force sense. Signal: you're given parameters (`n`, `e`, `c`) or source code implementing the crypto — the vulnerability is *in that code/those parameters* (small `e`, reused nonce, weak PRNG seed, predictable IV), not in guessing a passphrase.
* **Hash cracking** is its own sub-case: a hash alone means dictionary/rule-based attack (`hashcat`/`john`); a hash *plus* a partially-known input (a known salt, a known format) means constructing a targeted candidate list rather than a blind wordlist run.

RSA/AES/hash misuse challenges routinely chain out of forensics or RE (the parameters are extracted from a binary, a pcap, or a memory dump) and chain *into* whatever the decrypted plaintext turns out to be — don't assume the decrypted output is the flag; re-triage it.

See [Cryptography](cryptography.md) for XOR, RSA (small exponent, common modulus, Wiener's attack), AES padding oracles, lattice attacks, and ECC-specific attacks.

### Web Exploitation

Sub-types split by *where the trust boundary breaks*, and multiple vulnerability classes commonly chain within a single web challenge:

* **Recon-first challenges**: the vulnerability is invisible until you find a hidden endpoint, a `.git` directory, or a JS bundle leaking an API path. Always do recon even if the "obvious" vuln (a login form) is staring at you — the real bug is often one directory over.
* **Injection classes** (SQLi, SSTI, deserialization, command injection): signal is a form/parameter that clearly round-trips into a backend query, template, or object. These usually chain input → filter bypass → RCE/data exfil, all within the category.
* **Logic/access-control bugs** (IDOR, broken auth, JWT tampering): signal is the app *works fine* — there's no visible injection point, just a place where an ID, a role claim, or a token isn't checked properly. These often need a low-priv account first (register, or a "guest" cred handed to you) before the bug is reachable.
* **Server-as-a-relay** (SSRF): signal is any feature where the server fetches a URL on your behalf (webhooks, "import from URL," PDF/screenshot generators, image proxies) — chains naturally into cloud metadata theft or into reaching an otherwise-unroutable internal service that's a *second* challenge in disguise.

A web challenge that hands you a *file* (an export, a backup, a config) alongside the URL is a strong chain signal — re-triage that file with the cross-category guide above rather than treating the URL as the whole challenge.

See [Web Exploitation](web-exploitation.md) for SQLi/XSS/SSRF/SSTI/LFI/deserialization payloads, JWT attacks, and advanced techniques (request smuggling, cache poisoning, prototype pollution, GraphQL).

### Binary Exploitation (Pwn)

Sub-types are mostly about *which mitigation is off*, which tells you which primitive to reach for:

* **No canary / no NX**: classic stack buffer overflow, often straight to shellcode.
* **NX on, no PIE**: return-to-libc / ROP using fixed addresses.
* **PIE + full RELRO**: usually needs an info leak first (format string, a read primitive) before ROP is possible — treat the leak as its own mini-puzzle.
* **Heap challenges**: signal is `malloc`/`free` calls exposed through a menu-driven CLI ("allocate," "edit," "free" options) — look for use-after-free or double-free before anything else.
* **A `nc host:port` with no source/binary**: pure blind exploitation — recon the protocol by connecting manually first (`nc`, then script it) before assuming you need to find a leaked binary.

`checksec` is the fastest way to know which sub-type you're in — run it before reading a single line of disassembly.

Pwn challenges chain *in* from OSINT/forensics surprisingly often (the target libc version or an offset comes from a separate hint file) and chain *out* into RE if the binary itself needs to be understood before you know what to overflow.

See [Binary Exploitation](binary-exploitation.md) for the protections cheat-reference, format string attacks, heap exploitation (tcache poisoning, house-of-* techniques), ROP, shellcoding, kernel pwn, and seccomp escapes.

### Reverse Engineering

Sub-types depend on what you're actually reversing:

* **"Enter the right input" crackmes**: signal is a straightforward compare against user input. → static analysis to find the check, or just script the constraint (Z3/angr) instead of hand-tracing it.
* **Obfuscated/packed binaries**: signal is a decompiler producing garbage, or an entropy check flagging most of the binary as high-entropy (a packer). → unpack first (dump from memory after it self-decompresses) before real analysis.
* **VM-based obfuscation / custom bytecode**: signal is a giant `switch` statement over an opcode byte read from an array — you're reversing an interpreter, not the "real" logic; identify the opcode handlers before trying to trace program flow directly.
* **Managed-language binaries** (.NET, Java/JAR, Android/APK): don't reach for a disassembler first — decompilers (`dnSpy`, `jadx`, `jd-gui`) recover near-source-level code directly and are much faster.
* **Anti-debugging tricks**: signal is a binary that behaves differently under a debugger (crashes, hangs, or silently takes a different branch). → patch out the check or use a stealthier dynamic approach before assuming the logic itself is what's hard.

The output of an RE challenge (a discovered key, algorithm, or embedded string) frequently *is* the input to a Cryptography or Web challenge elsewhere in the same track — don't treat "I found the algorithm" as done if nothing flag-shaped came out.

See [Reverse Engineering](reverse-engineering.md) for static/dynamic analysis workflow, scripting the solve with angr/Z3, and firmware/embedded RE.

### OSINT & Misc

The broadest and most "chain-native" category — "Misc" exists specifically for challenges that don't fit elsewhere, so expect a jump into another category as the *punchline*, not the setup:

* **OSINT proper** (geolocation, username correlation, archived-content digging): signal is a photo, handle, or partial address with no file to analyze — the "tool" is search technique, not software. Cross-reference EXIF GPS data, shadow/object-height geolocation, reverse image search, and `Wayback Machine` snapshots against each other rather than expecting one source to hand you the answer.
* **Encoding identification**: often the very first step of a much longer chain from a different category (see the Cryptography section above) — treat a solved encoding as "layer peeled," not "challenge solved."
* **QR codes / barcodes**: signal is a visibly damaged, partial, or inverted-color code. → manual module reconstruction, not just re-scanning.
* **Jail/sandbox escapes** (pyjail and friends): signal is a REPL-like input that filters characters/keywords. → enumerate exactly what's blocked before trying payloads; the filter's blind spots are the whole challenge.
* **Esoteric programming languages**: signal is source code in an unfamiliar syntax with a name you don't recognize — identify the language first (often from the file extension or a distinctive keyword) before trying to hand-trace it.

See [OSINT & Misc](osint-and-misc.md) for geolocation deep-dives, Wayback Machine query patterns, DTMF/SSTV/modem audio decoding, and sandbox-escape technique lists.

### AI & Prompt Injection

Sub-types are about the trust boundary the model sits behind:

* **Direct extraction**: no filtering — signal is a chatbot with a system prompt containing a secret; try direct/rephrased asks first before anything fancier.
* **Guarded single-model**: a filter/refusal layer sits in front of one model. → format-shifting, roleplay/persona framing, completion attacks.
* **Two-LLM (guard-model) setups**: a separate model screens your input/output. → the target is convincing the *guard*, not just the underlying model; payload splitting and indirect side-channel leaks matter more here.
* **Agentic/tool-using setups**: the model can call tools (browse, execute, query a DB). → the "flag" may be reachable through a tool the model has access to rather than through the chat response directly — an injection payload aimed at making the *agent* take an action, not just say something.

Prompt-injection challenges can also be the delivery mechanism *for* another category — a jailbroken agent that can read files or hit internal URLs turns straight into an SSRF/LFI-style chain.

See [AI & Prompt Injection](ai-and-prompt-injection.md) for extraction phrasings, format-shifting, multi-turn/crescendo attacks, and multi-modal injection.

## Worked chain examples (illustrative)

These are hypothetical but representative of how real multi-stage challenges are typically built — use them to sanity-check whether you're "actually done" or just found the next wrapper.

1. **Forensics → Crypto → Web.** A JPEG has an LSB-encoded payload (Forensics) that turns out to be a password-protected zip; cracking it with a small custom wordlist (hinted by the challenge author's Twitter handle, OSINT) reveals an RSA public key and ciphertext with a suspiciously small `e` (Crypto: low-exponent attack recovers the plaintext); the plaintext is a set of login credentials for the challenge's web app (Web), where the real flag lives in an admin-only page.
2. **Network forensics → Reverse Engineering → Crypto.** A `.pcap` contains an FTP transfer of a stripped Linux binary (Forensics); decompiling it reveals a hardcoded XOR key used to "license check" a serial (RE); that same XOR key, applied to a second high-entropy string embedded in the binary's `.rodata`, decodes to the flag directly (Crypto/XOR) — no network interaction needed at all despite the pcap.
3. **OSINT → Web.** A challenge gives only a username and a company name — searching finds a public GitHub repo (OSINT) with a `.env` file accidentally committed in an old git history (`git log -p`), containing an API key that authenticates against the challenge's web API (Web) to retrieve the flag.

## Out-of-the-box thinking checklist (when you're stuck)

* **Re-read the title and description literally *and* figuratively.** Puns, unusual phrasing, and specific nouns are frequently the only hint you get toward which technique or tool to use.
* **Question what the challenge deliberately withheld.** No visible flag format, no obvious login form, no stated file type — absence of the expected hint is itself a signal that you're meant to find it elsewhere (often in a different file or a different category entirely).
* **Try the opposite of what your tools suggest.** If `file` says "data" with no match, deliberately test it as each plausible category in turn (corrupted image, encrypted archive, raw memory/disk dump, raw network capture) rather than getting stuck on one guess.
* **Open it in a hex editor even after automated tools return nothing.** `binwalk`/`strings`/`exiftool` only recognize known signatures — a custom or intentionally mangled format won't show up, but will be obvious to a human eye scanning for repeating structure.
* **Check exact byte counts and sizes.** 16/32/64-byte blobs hint at AES block/key sizes or common hash-digest lengths; suspiciously round numbers often aren't coincidence.
* **If multiple files are given, compare them before analyzing them individually.** Diff, XOR, or overlay them — split-secret and multi-part puzzles are common and easy to miss if you triage each file in isolation.
* **If source code is provided, diff it against the real upstream project** (when it's a modified open-source app) — the injected vulnerability is usually a small, deliberate deviation that's easy to spot in a diff and easy to miss by reading in isolation.
* **Search unique strings verbatim** (a variable name, a comment, an unusual function name, a file hash) — challenge assets get reused across events, and a stray string can turn up a public writeup of the exact same challenge.
* **Don't stop at the first flag-shaped string.** Decoy flags matching the expected format are a known troll technique — submit it, but keep working the chain if the description or points value suggests more depth.
* **When completely stuck, re-run the universal triage workflow on every artifact you've produced so far, not just the original file.** The layer you skipped past three steps ago is usually where the actual puzzle starts.

## General tools worth having installed

| Tool | Use |
| --- | --- |
| [CyberChef](https://gchq.github.io/CyberChef/) | Swiss-army knife for encoding/decoding, "The Cyber Chef" — try this before writing a script |
| `pwntools` (Python) | Binary exploitation / pwn scripting |
| [Ghidra](https://ghidra-sre.org/) / [IDA Free](https://hex-rays.com/ida-free/) | Static reverse engineering / decompilation |
| `binwalk` | Extract embedded files/firmware from a blob, plot entropy |
| [dCode](https://www.dcode.fr/) | Identify and solve classic ciphers |
| `jq` | Parse/query JSON output from tools and APIs |
| Docker | Reproduce challenge environments cleanly |
| `exiftool` | Metadata inspection across image/audio/video/document formats |
| `zsteg` / `steghide` | Automated LSB/stego checks on PNG/BMP/JPG |
| Volatility 3 | Memory image analysis |
| Wireshark / `tshark` | pcap analysis, stream reconstruction |

## Flag format

Most CTFs use a fixed flag format, e.g. `flag{...}` or `CTF{...}`. Always check the challenge/scoreboard rules first — grepping for the exact format saves a lot of time once you have candidate output, and is worth re-running after *every* decode step, not just at the end:

```
grep -oE "flag\{[^}]*\}" output.txt
```
