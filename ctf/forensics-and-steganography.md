# Forensics & Steganography

## First steps on any file

1. **Identify the real type, don't trust the extension.**

```
file <filename>
```

2. **Check metadata.**

```
exiftool <filename>
```

3. **Look for embedded/appended files** (a common trick: a valid PNG with a ZIP appended after the `IEND` chunk).

```
binwalk <filename>
binwalk -e <filename>   # extract anything found
```

4. **Diff against a hex view** if a "clean" reference file is available:

```
xxd <filename> | less
cmp -l file1 file2
```

## Image Steganography

**Tools/Commands:**

* `zsteg image.png` — checks common LSB-encoding patterns in PNG/BMP automatically, very high hit rate
* `steghide extract -sf image.jpg` — try an empty passphrase first, then wordlist:

```
stegcracker image.jpg rockyou.txt
```

* `exiftool` / `strings image.jpg` for hidden text in metadata/comments
* Check image dimensions vs. file size — a resolution mismatch or a broken height field can indicate hidden trailing data (fix the height field in a hex editor to reveal cropped content)
* LSB manual inspection: [StegSolve](http://www.caesum.com/handbook/Stegsolve.jar) — cycle through bit planes and color filters

## Audio Steganography

**Tools/Commands:**

* [Sonic Visualiser](https://www.sonicvisualiser.org/) / Audacity spectrogram view — data is sometimes hidden visually in the frequency spectrum (drawn text/QR codes)
* `binwalk` still applies — audio files can have appended archives too
* DTMF tones / Morse code hidden in the waveform — decode by ear or with an online DTMF decoder

## Memory Forensics

**Tools/Commands:**

* [Volatility 3](https://github.com/volatilityfoundation/volatility3):

```
vol -f memdump.raw windows.info          # identify profile/OS
vol -f memdump.raw windows.pslist        # running processes
vol -f memdump.raw windows.cmdline       # process command lines
vol -f memdump.raw windows.filescan      # find files referenced in memory
vol -f memdump.raw windows.dumpfiles --pid <PID>
```

* Look for suspicious processes, injected shellcode regions (`malfind` plugin), and cleartext credentials in process memory (browsers, mimikatz-style LSASS dumps)

## Disk Forensics

**Tools/Commands:**

* `mmls disk.img` — list partitions (The Sleuth Kit)
* `mount -o ro,loop disk.img /mnt/evidence` — mount read-only for browsing
* `autopsy` — GUI wrapper around The Sleuth Kit for full disk analysis
* Recover deleted files: `photorec` / `foremost -i disk.img -o output/`

## PCAP / Network Forensics

**Tools/Commands:**

* Wireshark: `Follow > TCP/HTTP Stream` to reconstruct a full conversation or transferred file
* Extract transferred files directly: `File > Export Objects > HTTP` (or `SMB`/`DICOM` etc.)
* CLI equivalent for scripting: `tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri`
* Reassemble a file carved from raw bytes: `binwalk -e extracted_stream.bin`

## Archive / Document Forensics

**Tools/Commands:**

* Password-protected ZIP: `zip2john file.zip > hash.txt && john hash.txt` or `fcrackzip -u -D -p rockyou.txt file.zip`
* Malicious Office docs: `oletools` — `olevba document.docm` dumps embedded VBA macros
* PDFs: `pdf-parser file.pdf` / `peepdf file.pdf` to inspect objects and embedded JavaScript/files

## General tips

* When stuck, re-run `binwalk` and `exiftool` on *every* file you extract — stego/forensics challenges love nesting (image → zip → text → base64 → flag).
* Keep a scratch directory and extract iteratively rather than trying to solve everything from the original blob.

## Advanced Techniques

### Advanced Volatility 3 Usage

**Timeline reconstruction:**

```
vol -f memdump.raw timeliner.Timeliner
```

Correlates timestamps across plugins (process creation, file objects, registry key modification) into one chronological view — useful for establishing what happened around a suspicious event before you know which process/file to focus on.

**`malfind` workflow for injected code:**

```
vol -f memdump.raw windows.malfind
```

1. Look for memory regions flagged `PAGE_EXECUTE_READWRITE` with no backing file (private, not mapped from a DLL/EXE) — a strong injection indicator.
2. Cross-reference the flagged PID with `windows.pslist`/`windows.pstree` to check if the process is a plausible injection target (`explorer.exe`, `svchost.exe`).
3. Dump the flagged region for static analysis or YARA scanning:

```
vol -f memdump.raw windows.vadyarascan --pid <PID> --yara-rules rules.yar
```

4. `windows.dumpfiles --pid <PID>` to pull backing files for comparison against known-good versions.

**Persistence hunting via registry:**

```
vol -f memdump.raw windows.registry.printkey --key "Microsoft\Windows\CurrentVersion\Run"
vol -f memdump.raw windows.registry.printkey --key "Microsoft\Windows\CurrentVersion\RunOnce"
```

Check standard autorun locations, `Services` keys, and scheduled-task registration keys for anything referencing an unfamiliar binary path — the classic persistence-in-a-memdump challenge.

### Blockchain Forensics

**Tracing an address:**

* Bitcoin: a block explorer ([blockchain.com](https://www.blockchain.com/explorer), [mempool.space](https://mempool.space/)) for manual graph-walking, or script it:

```
bitcoin-cli getrawtransaction <txid> 1
```

* Ethereum: [Etherscan](https://etherscan.io/) for manual tracing; `web3.py` for scripted graphs:

```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('https://rpc-url'))
tx = w3.eth.get_transaction('0x...')
balance = w3.eth.get_balance('0xAddress')
```

* Look for address reuse linking a "clean" address to a known one (exchange deposit address, an address seen elsewhere in the challenge), and round-trip amounts tying transactions together across hops.

**Extracting wallet data from a disk image:**

* Locate wallet files by known paths: `wallet.dat` (Bitcoin Core), `keystore/` JSON files (Ethereum/geth), browser-extension storage (MetaMask's IndexedDB/LevelDB under the extension's profile directory).
* `wallet.dat` is a Berkeley DB file — dump keys with `bitcoin-wallet` tooling or `pywallet`; if encrypted, the passphrase is often the crackable secret (`john`/`hashcat -m 11300` support Bitcoin/Litecoin `wallet.dat` hashes).
* MetaMask/browser-extension keystores are password-encrypted JSON (AES) — identify the KDF/cipher and brute-force the passphrase the same way.

### Network Forensics Deep-Dive

**Decrypting TLS in Wireshark with a known session key log:**

1. If challenge material includes an `SSLKEYLOGFILE`-format log (or a companion agent/binary can be made to dump one), point Wireshark at it: `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`.
2. Wireshark decrypts the TLS streams live — `Follow > TLS Stream` then works exactly like an HTTP stream.
3. Without a keylog file but with an RSA private key and a non-(EC)DHE cipher suite (static RSA key exchange), Wireshark can decrypt directly via `Protocols > TLS > RSA keys list` — this does not work against forward-secret suites, which cover most modern traffic.

**Detecting DNS tunneling:**

* Abnormally high volume/frequency of `TXT` (or `NULL`/`CNAME`) queries to a single unusual domain — legitimate traffic rarely needs many TXT lookups in a short window.
* High entropy in subdomain labels (base32/base64-looking labels like `aGVsbG8gd29ybGQ.tunnel.evil.com`) is the other strong tell — tunneling tools encode exfiltrated data into subdomain labels.

```
tshark -r capture.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name | sort | uniq -c | sort -rn
```

* Decode the collected labels (base32/base64/hex depending on the tunneling tool — `iodine` and `dnscat2` use distinct framing) to reconstruct the exfiltrated payload.
