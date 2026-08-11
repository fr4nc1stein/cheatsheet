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

## Advanced Techniques

### Image Geolocation Deep-Dive

**Description:** EXIF GPS is stripped in almost every serious challenge. Geolocation then becomes a systematic narrowing exercise: continent → country → region → city → exact building. Work top-down and record what each clue rules *out*, not just what it suggests.

**1. Text, signage, and script**

* Any visible text is the highest-value clue. Even blurred text gives you the **script** (Latin/Cyrillic/Arabic/Devanagari/CJK), which alone eliminates most of the world.
* Within Latin script, diacritics narrow hard: `ő/ű` → Hungarian, `ł/ż` → Polish, `ă/ș/ț` → Romanian, `ğ/ı/ş` → Turkish, `å/ø/æ` → Nordic.
* Phone numbers on shopfronts/vans give a country code and often an area code — search the number directly.
* Business names, franchise brands, and even a regional supermarket chain pin a country immediately. Domain TLDs on advertising do the same.
* Language-detect fragments, then run the text as a literal Google/Yandex search in that language.

**2. Vehicles and road infrastructure**

* **Which side of the road** traffic drives on splits the world roughly 65/35 — check parked car orientation, steering-wheel side, or road markings.
* **License plate format:** aspect ratio, colour, and the EU blue band; yellow rear plates (UK, Netherlands); the character grouping pattern itself is often country-unique even when unreadable.
* **Road markings:** centre-line colour (yellow in the Americas/Japan, white across most of Europe), dashed vs solid conventions, crosswalk styles (zebra vs ladder vs the Japanese ladder-with-outline).
* **Bollards, guardrails, and chevrons** are strongly national — GeoGuessr-style "bollard-spotting" transfers directly to CTF work.
* Road sign shapes/colours: European blue motorway signs vs green, US green guide signs, the distinctive Australian/NZ styles.

**3. Utility poles and power lines**

One of the most reliable and most-overlooked signals:

* Wooden vs concrete vs steel-lattice poles; concrete poles with visible holes are common in parts of Eastern Europe and Latin America.
* Insulator count and arrangement, crossarm shape, transformer can style (US "trash can" cylinders vs European box transformers).
* Overhead vs buried distribution — a fully buried network suggests newer/wealthier suburban development.

**4. Architecture, vegetation, and biome**

* Roof material and pitch (steep = snow load; flat = arid), window shutter style, balcony conventions, wall render vs brick vs timber.
* Vegetation: eucalyptus (Australia, but also Iberia/California), palm species, birch/conifer belts, terra-rossa red soil (Australia/Brazil/Mediterranean).
* Sky/haze, snow line, and vegetation state also give you a **season**, which constrains dates.

**5. Shadow analysis for latitude and time**

**Description:** Shadow direction and length are a physical constraint on where and when the photo was taken.

* In the **northern** hemisphere the sun is due south at solar noon, so midday shadows point roughly north; in the **southern** hemisphere they point roughly south. A near-zero-length midday shadow means you are within the tropics.
* Shadow **direction** gives you the sun's azimuth; shadow **length** relative to the object's height gives the solar elevation: `elevation = atan(height / shadow_length)`.
* Combine elevation + date to solve for latitude, or elevation + known location to solve for time of day.

```python
import math
# object height and shadow length in the same units (pixels work if both are measured
# in the same plane and the object is vertical)
height, shadow = 1.8, 3.1
print(math.degrees(math.atan(height / shadow)))   # solar elevation in degrees
```

* [SunCalc](https://suncalc.org/) — drop a pin, set a date/time, and it renders the sun's azimuth and the resulting shadow direction. Use it in reverse to **verify or disprove a claimed date/time**: if the challenge says "taken 14:00 on 3 June" and SunCalc puts the shadow 90° away from the photo, the claim (or your candidate location) is wrong.
* Cross-check against visible clocks, sun position in reflections, and artificial-vs-natural lighting.

**6. Satellite and street-level confirmation**

* Once you have a candidate area, switch to **overhead** matching: building footprint, roof colour, parking-lot layout, sports pitch orientation, and the shape of the road junction.
* [Google Earth Pro](https://www.google.com/earth/versions/) historical imagery (the clock icon) steps back through years of captures — essential when a building was demolished, repainted, or built after the current imagery.
* Street View: check the capture date in the corner; an older capture may match a photo that current imagery does not.
* Cross-reference with [OpenStreetMap](https://www.openstreetmap.org/) which often has more detailed labelling of small features than commercial maps.

**7. Reverse image search — use all of them**

| Engine | Strength |
| --- | --- |
| [Yandex](https://yandex.com/images/) | Clearly the strongest for faces, landmarks, and visually-similar (not just identical) matching. Try it first. |
| [Google Lens](https://lens.google.com/) | Best for objects, text-in-image, and products |
| [Bing Visual Search](https://www.bing.com/visualsearch) | Different index; sometimes finds what the others miss |
| [TinEye](https://tineye.com/) | Exact/edited copies and *oldest* occurrence — good for tracing an image's origin |
| [PimEyes](https://pimeyes.com/) | Face-specific (limited free use; be mindful of the ethics and of challenge rules) |

* Crop to the distinctive element (a sign, a statue, a skyline) and search the crop separately — full-frame searches often return generic noise.
* Search the same crop rotated/mirrored if the image may have been flipped.

### Person and Username Correlation

**Description:** A single confirmed handle is a pivot point. The technique is to enumerate where that handle exists, confirm which hits are actually the same person, then harvest new identifiers (email, real name, alternate handle) from the confirmed accounts and repeat.

**Tools/Commands:**

```
sherlock <username>                          # username across 400+ sites
maigret <username> --html                    # broader, extracts and reports found IDs/bio data
holehe <email@example.com>                   # which sites have an account for this EMAIL
```

* [sherlock](https://github.com/sherlock-project/sherlock) — the standard first sweep; fast, high false-positive rate on sites with loose 404 handling.
* [maigret](https://github.com/soxoj/maigret) — sherlock's more thorough successor: more sites, and it parses the pages it finds to pull out bios, other usernames, and linked accounts automatically.
* [holehe](https://github.com/megadose/holehe) — pivots on **email** rather than username, using password-reset/registration oracles to test account existence without logging in.
* [WhatsMyName](https://whatsmyname.app/) — browser-based, community-maintained site list; good for manual cross-checking a tool's hits.

**Confirming a match is the same person (tool output is only a candidate list):**

* [ ] **Profile photo** — reverse-image the avatar; the same avatar across platforms is strong evidence. Also check for the same photo *cropped differently*, which indicates a shared source file.
* [ ] **Writing style** — vocabulary, punctuation habits, emoji usage, signature sign-offs, consistent typos, timezone of posting activity.
* [ ] **Bio content** — repeated phrases, the same linked website, the same city/employer.
* [ ] **Account creation date and ID ordering** — sequential numeric IDs place account creation in time.
* [ ] **Social graph overlap** — the same followers/friends appearing across two accounts.

**Pivoting outward from a confirmed account:**

* Public commit history on GitHub leaks a real email: `git log --format='%ae %an' | sort -u` on any clone, or hit `https://api.github.com/users/<user>/events/public` and read the commit author fields.
* Gravatar: `https://www.gravatar.com/<md5-of-lowercased-email>.json` returns a profile if one exists — an email→profile pivot.
* Old forum posts, mailing-list archives, and Q&A sites (Stack Overflow) tie a handle to technical details and sometimes to a real name.
* Any leaked/registered domain from a WHOIS record, and reverse-WHOIS on that registrant.

### Historical and Archived Content

**Description:** The answer is frequently in a version of the page that no longer exists.

**Wayback Machine:**

```
# All snapshots of a URL
https://web.archive.org/web/*/target.com/*

# Nearest snapshot to a timestamp (YYYYMMDDhhmmss)
https://web.archive.org/web/20180101000000/http://target.com/
```

The **CDX API** is the right tool for enumerating archived URLs rather than clicking through the UI:

```
# Every unique archived path under a host
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com*&output=text&fl=original&collapse=urlkey" | sort -u

# JSON with timestamps, status codes and MIME types, filtered to interesting files
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com*&output=json&fl=timestamp,original,statuscode,mimetype&filter=original:.*\.(pdf|xlsx|sql|bak|txt|json)$&collapse=urlkey"

# Snapshots of one URL within a date range
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/secret&from=2015&to=2020&output=json"
```

Useful CDX parameters: `matchType=prefix|domain|host`, `collapse=digest` (drop identical captures), `limit=`, `filter=statuscode:200`.

* [waybackurls](https://github.com/tomnomnom/waybackurls) — `echo target.com | waybackurls` for the same enumeration as a one-liner.
* [gau](https://github.com/lc/gau) — pulls from Wayback, Common Crawl, and URLScan together.

**Other archives:**

* [archive.today / archive.ph](https://archive.ph/) — snapshots pages the Wayback Machine refuses (paywalls, `robots.txt`-excluded sites, social media). Independent index, always worth a second check.
* Search-engine caches: Google's `cache:` is effectively retired, but Bing still serves cached copies, and both index page text that survives the page itself.
* [Common Crawl](https://commoncrawl.org/) — bulk web corpus, queryable by URL index.

**Recovering deleted social content:**

* Wayback/archive.today snapshots of the profile page.
* Google/Bing cache and the search-result snippet text itself (the snippet often contains the deleted sentence).
* Quote-tweets, screenshots, and replies from others that quoted the deleted post.
* Reddit: [reveddit](https://www.reveddit.com/) surfaces removed comments; pushshift-style mirrors for historical data.
* RSS readers, newsletter archives, and aggregator sites that mirrored the original feed.

### Transport and Vehicle Tracking

**Description:** A photo of a plane, a ship, or a train is a timestamp-and-location oracle, because these vehicles broadcast their position publicly and that history is archived.

**Aircraft (ADS-B):**

* [ADS-B Exchange](https://globe.adsbexchange.com/) — unfiltered (it does not honour blocking requests, unlike the commercial trackers) and supports historical playback by date. The best option for challenges.
* [FlightRadar24](https://www.flightradar24.com/) and [FlightAware](https://flightaware.com/) — good UI, historical flight logs per registration or flight number.
* Read the **registration** (tail number) off the fuselage: `N` = US, `G-` = UK, `D-` = Germany, `VH-` = Australia, `JA` = Japan, `F-` = France. Look it up in the national registry (FAA N-number inquiry, UK CAA G-INFO) for owner, type, and build year.
* Livery, engine type, and winglet shape identify the model when the registration is not legible.
* Reverse the workflow for geolocation: if you know roughly where and when a photo was taken and a specific aircraft is visible, historical ADS-B narrows the *exact* minute — or, given the aircraft and time, tells you where the photographer stood.

**Ships (AIS):**

* [MarineTraffic](https://www.marinetraffic.com/) and [VesselFinder](https://www.vesselfinder.com/) — live and historical vessel positions, port calls, and photos.
* Identify by **name on the hull**, **IMO number** (permanent, 7 digits), or **MMSI** (9 digits, first three are the country's MID code).
* Port-call history places a specific ship at a specific dock on a specific date — perfect for confirming a harbour photo.

**Trains and transit:**

* Rolling-stock livery and unit numbers identify the operator and often the exact route.
* National open-data feeds (GTFS/GTFS-RT) and enthusiast sites like [Open Railway Map](https://www.openrailwaymap.org/) map lines, signals, and station layouts.
* Station signage typography and platform furniture are highly operator-specific — a strong geolocation clue in their own right.
* Timetables constrain time-of-day: if the challenge shows a train at a platform, the departure board narrows the window.

### Satellite Imagery and Mapping Data

**Satellite comparison:**

* [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/) — free Sentinel-2 (10 m, ~5-day revisit) and Landsat imagery with a date slider. Use it to date an event: find the first capture where a structure/scar/vessel appears.
* [NASA Worldview](https://worldview.earthdata.nasa.gov/) — daily global imagery, good for fires, floods, and smoke plumes.
* [Google Earth Pro](https://www.google.com/earth/versions/) historical layer for high-resolution change detection.
* Compare the same coordinates across providers (Google, Bing, Yandex, Esri) — capture dates differ by years, so one may show what the others do not.

**OpenStreetMap raw data via Overpass:**

**Description:** Instead of eyeballing a map, query OSM's database for every feature matching a description. If the clue is "a lighthouse within sight of a windmill", Overpass will list every candidate pair in a region.

Run these at [Overpass Turbo](https://overpass-turbo.eu/):

```
// All lighthouses in the current map view
[out:json][timeout:25];
node["man_made"="lighthouse"]({{bbox}});
out body geom;
```

```
// Named feature search across a country
[out:json][timeout:60];
area["ISO3166-1"="PT"][admin_level=2]->.a;
nwr["man_made"="water_tower"](area.a);
out center;
```

```
// Two feature types near each other (church within 300m of a school)
[out:json][timeout:60];
{{geocodeArea:"Ghent"}}->.a;
way["amenity"="place_of_worship"](area.a)->.churches;
node(around.churches:300)["amenity"="school"];
out center;
```

* Useful tag families: `amenity`, `man_made`, `historic`, `tourism`, `natural`, `railway`, `aeroway`, `power`.
* `out center;` gives one coordinate per way/relation — easiest to plot.
* The [OSM Wiki tag pages](https://wiki.openstreetmap.org/wiki/Map_features) are the reference for what tag to query.

### Esoteric Programming Languages

**Description:** A "misc" file that looks like corrupted data is often source code. Recognize by character signature, then run it in an online interpreter.

| Signature | Language | Notes |
| --- | --- | --- |
| Only `> < + - . , [ ]` | **Brainfuck** | The classic; long runs of `+++++` |
| Only spaces, tabs, and newlines (file *looks* empty) | **Whitespace** | Reveal with `cat -A` — all other characters are comments |
| `Ook. Ook? Ook!` repeated | **Ook!** | 1:1 mapping to Brainfuck |
| Dense random-looking printable ASCII, `D'`, `(=<`, `#"` | **Malbolge** | Deliberately near-impossible to write; assume a known payload and decode |
| A PNG/GIF of coloured blocks | **Piet** | Program *is* the image — 20 hues + black/white, run with `npiet` |
| `+++++[->` with `!` and `?` sprinkled | Brainfuck dialect | Try common variants before assuming a new language |
| Long strings of `zzzz`/`ZZ` and vowel clusters | **Chicken**, **COW**, **LOLCODE** | Look for the keyword vocabulary (`moo`, `HAI`/`KTHXBYE`) |
| Stacked ASCII art in a 2D grid with `>v<^` | **Befunge** | 2D instruction pointer; direction characters give it away |
| `⍋⍴⍨⌽∘` APL glyphs | **APL/J/K** | Array languages, not strictly esoteric but read as noise |

```
# Local interpreters
bf program.bf                     # or beef / brainfuck (packages vary)
npiet program.png                 # Piet
befunge program.bf93
cat -A file.ws                    # confirm Whitespace: only $, ^I and spaces
```

* [esolangs.org](https://esolangs.org/wiki/Main_Page) — the canonical wiki; every language above has a page listing interpreters.
* [dcode.fr](https://www.dcode.fr/) and [CyberChef](https://gchq.github.io/CyberChef/) both have Brainfuck/Ook/Malbolge decoders.
* [copy.sh/brainfuck](https://copy.sh/brainfuck/) — in-browser Brainfuck with a debugger/step view, useful when the program reads input.
* If the program expects **input**, the flag is usually derived from what you feed it — instrument the interpreter or trace the tape rather than guessing.

### Advanced QR and Barcode Recovery

**Description:** Damaged codes are recoverable far more often than they look, because QR carries Reed–Solomon error correction: level L ~7%, M ~15%, Q ~25%, H ~30% of codewords can be lost and still decode.

**Recovery workflow:**

1. **Try decoding as-is first** — `zbarimg image.png`, and also try a phone camera and an online decoder; different decoders have very different tolerance.
2. **Fix the geometry.** Deskew/perspective-correct so the modules land on a clean grid, restore contrast to pure black/white, and rebuild the three **finder patterns** (the corner squares) and the timing patterns (the alternating row/column between them) — these are fixed and can be redrawn exactly.
3. **Rebuild missing regions manually.** [QRazyBox](https://merricx.github.io/qrazybox/) is purpose-built for this: draw the known modules on a grid, mark unknowns, and it applies error correction and brute-forces the remainder. It also handles the format-information bits (mask pattern + EC level), which are the usual reason a mostly-intact code will not scan.
4. **Invert.** A colour-inverted QR (white modules on black) fails in many decoders — invert and retry.
5. **Check the version/size.** Module count tells you the QR version: 21×21 = v1, 25×25 = v2, +4 per version. A miscounted grid is a common self-inflicted failure.

**Other cases:**

* Rotation does not matter (the finder patterns encode orientation), but a **mirrored** code does — flip it.
* Micro QR, Aztec, Data Matrix, and PDF417 all look QR-ish; `zbarimg` handles several, and online multi-format readers cover the rest.
* 1D barcodes: identify the symbology by guard-pattern and digit count (EAN-13, UPC-A, Code 128, Code 39) — a partially cut barcode can be read manually from the bar-width pattern using a symbology table.
* A QR split into pieces across several challenge files is a common trick — reassemble before decoding.

### Audio: DTMF, SSTV, and Modem Signals

**Description:** If a challenge hands you audio that is not music or speech, it is a signal to be demodulated. Open it in a spectrogram first ([Audacity](https://www.audacityteam.org/) or [Sonic Visualiser](https://www.sonicvisualiser.org/)) — the spectrogram identifies the mode instantly.

| Spectrogram appearance | Mode | Decode with |
| --- | --- | --- |
| Short bursts, two simultaneous tones each | **DTMF** (phone keypad) | `multimon-ng -a DTMF -t wav in.wav`, or an online DTMF decoder |
| Slow sweeping horizontal lines, ~1500–2300 Hz, 1–2 min long | **SSTV** | [sstv](https://github.com/colaclanth/sstv) (`sstv -d in.wav -o out.png`), QSSTV, or RX-SSTV |
| Regular on/off single tone, long/short pattern | **Morse (CW)** | `multimon-ng -a MORSE_CW`, or decode by ear from the spectrogram |
| Two closely-spaced alternating tones | **FSK / RTTY / AFSK1200** | `multimon-ng -a AFSK1200 -a POCSAG512 -t wav in.wav` |
| Harsh wideband hiss with structure | Modem/fax/packet | Identify the standard first, then a soft-modem decoder |
| Readable text/QR *drawn* in the spectrogram | Not a signal — visual stego | Just read it off the spectrogram view |

```
# Convert to the mono 22050 Hz WAV that most decoders expect
sox input.mp3 -r 22050 -c 1 output.wav

# multimon-ng from a raw stream
sox in.wav -t raw -esigned-integer -b16 -r 22050 - | multimon-ng -t raw -a DTMF -

# Slow a signal down without changing pitch (helps manual Morse reading)
sox in.wav out.wav tempo 0.5
```

**DTMF frequency pairs** (for manual reading off a spectrogram — each keypress is one low + one high tone):

| | 1209 Hz | 1336 Hz | 1477 Hz |
| --- | --- | --- | --- |
| **697 Hz** | 1 | 2 | 3 |
| **770 Hz** | 4 | 5 | 6 |
| **852 Hz** | 7 | 8 | 9 |
| **941 Hz** | * | 0 | # |

* SSTV mode matters (Martin M1, Scottie S1, Robot 36…): the VIS header at the start encodes it, and most decoders detect it automatically — if the output is skewed or colour-shifted, force the mode manually.
* If a decode is garbled, check the sample rate first; resampling artefacts break more decodes than actual signal damage.
* Reversed audio, changed playback speed, and one channel of a stereo file carrying a different signal (`sox in.wav out.wav remix 2`) are all common wrappers around an otherwise standard mode.
