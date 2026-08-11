# Getting Started

General approach and tooling for CTF challenges, organized by category. Unlike a pentest engagement, CTF challenges are usually self-contained (a file, a binary, a URL) and the goal is a flag, not persistence — so the workflow is more "identify → analyze → exploit/decode → extract flag."

**Category cheatsheets:**

* [Web Exploitation](web-exploitation.md)
* [Binary Exploitation (Pwn)](binary-exploitation.md)
* [Reverse Engineering](reverse-engineering.md)
* [Cryptography](cryptography.md)
* [Forensics & Steganography](forensics-and-steganography.md)
* [OSINT & Misc](osint-and-misc.md)

## First steps on any challenge file

1. **Identify the file type** — don't trust the extension.

```
file <filename>
```

2. **Look for embedded strings / flag format hints.**

```
strings -n 8 <filename> | grep -iE "flag|ctf|key|pass"
```

3. **Check metadata.**

```
exiftool <filename>
```

4. **Diff against a known-good reference** if one is available (e.g. a "before" image/binary), byte for byte:

```
cmp -l file1 file2
```

5. **Hash it** — sometimes the flag *is* a hash, or the challenge reuses a known file (check hash on VirusTotal / hash lookup sites).

```
sha256sum <filename>
```

## General tools worth having installed

| Tool | Use |
| --- | --- |
| [CyberChef](https://gchq.github.io/CyberChef/) | Swiss-army knife for encoding/decoding, "The Cyber Chef" — try this before writing a script |
| `pwntools` (Python) | Binary exploitation / pwn scripting |
| [Ghidra](https://ghidra-sre.org/) / [IDA Free](https://hex-rays.com/ida-free/) | Static reverse engineering / decompilation |
| `binwalk` | Extract embedded files/firmware from a blob |
| [dCode](https://www.dcode.fr/) | Identify and solve classic ciphers |
| `jq` | Parse/query JSON output from tools and APIs |
| Docker | Reproduce challenge environments cleanly |

## Flag format

Most CTFs use a fixed flag format, e.g. `flag{...}` or `CTF{...}`. Always check the challenge/scoreboard rules first — grepping for the exact format saves a lot of time once you have candidate output:

```
grep -oE "flag\{[^}]*\}" output.txt
```
