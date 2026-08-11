# OSINT & Misc

## OSINT

**Description:** Find publicly available information tied to a person, image, or piece of infrastructure to answer the challenge question.

**Tools/Commands:**

* **Image geolocation:** check EXIF first (`exiftool image.jpg`), then work from visual clues — signage/language, vegetation, road markings, sun angle — cross-referenced with Google Street View/Maps
* **Reverse image search:** Google Images, [Yandex](https://yandex.com/images/) (often better for faces/landmarks), [TinEye](https://tineye.com/)
* **Username/account correlation:** `sherlock <username>` (checks a username across many platforms), [WhatsMyName](https://whatsmyname.app/)
* **Domain/infra recon:** `whois <domain>`, `theHarvester -d <domain> -b all` for emails/subdomains, [crt.sh](https://crt.sh/) for certificate transparency logs (reveals subdomains)
* **Social media:** check post history/likes/tags for cross-platform username reuse; [Google dorks](https://www.exploit-db.com/google-hacking-database) (`site:`, `filetype:`, `intitle:`) for indexed leftovers
* **Metadata everywhere:** PDFs, Office docs, and images often retain author names, GPS, and software versions — always `exiftool` a provided file even in a non-forensics challenge

## Scripting / Automation

**Description:** Misc challenges often just need you to talk to a service programmatically (a remote `nc` service that asks a math question every round, an API that rate-limits, etc.).

**pwntools template for a `nc` service:**

```python
from pwn import *
io = remote('host', 1337)
io.recvuntil(b'question: ')
q = io.recvline().strip()
answer = eval(q)  # only for trusted, self-generated CTF challenge input
io.sendline(str(answer).encode())
io.interactive()
```

**Requests template for a web API:**

```python
import requests
s = requests.Session()
r = s.post('http://target/api/login', json={'user': 'a', 'pass': 'b'})
print(r.json())
```

## Encoding identification

**Description:** Misc/crypto challenges frequently stack multiple encodings. Recognize them on sight:

| Pattern | Likely encoding |
| --- | --- |
| Ends in `=` or `==`, charset `A-Za-z0-9+/` | Base64 |
| Only `0-9a-f`, even length | Hex |
| Only `2-7A-Z=` | Base32 |
| Words separated by `-`/spaces, all lowercase dictionary words | Base58/mnemonic or a wordlist cipher |
| `%XX` sequences | URL encoding |
| Groups of `.`/`-` | Morse code |

**Tool:** run unknown blobs through [CyberChef's "Magic" wand](https://gchq.github.io/CyberChef/) first — it auto-detects and chains common encodings.

## QR Codes / Barcodes

**Tools/Commands:**

* `zbarimg image.png` — decode a QR/barcode from an image file directly
* If the QR is damaged/partial, try reconstructing it in an image editor before decoding — QR has built-in error correction up to ~30% (level H)

## Jail / Sandbox Escapes (misc/pyjail)

**Description:** A restricted Python (or other language) REPL where banned keywords/builtins block the obvious `os.system("sh")`.

**Common bypass building blocks:**

```python
().__class__.__bases__[0].__subclasses__()  # find a usable class without naming it directly
[c for c in ().__class__.__bases__[0].__subclasses__() if 'warning' in c.__name__.lower()][0]()._module.__builtins__['__import__']('os').system('sh')
```

* If `import`/`os`/`exec` etc. are string-blocked, obfuscate via string concatenation, `chr()` codes, or unicode confusables
* Check exactly what's filtered (keyword vs. substring) — a keyword filter is trivially bypassed with e.g. `__imp` + `ort__`

## General misc tips

* Read the challenge description and file names literally — "misc" categories often hide the real hint in flavor text.
* Check if the challenge is a known one (title, description phrasing) — searching it can reveal the underlying technique class even without spoiling this instance.
* Keep [CyberChef](https://gchq.github.io/CyberChef/) open in a tab at all times; it covers a large fraction of misc/crypto one-liners without writing any code.
