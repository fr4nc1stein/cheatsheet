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
