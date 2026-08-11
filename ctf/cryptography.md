# Cryptography

## First steps

1. Identify what you're looking at — ciphertext, an algorithm name, or just parameters (`n`, `e`, `c` almost always means RSA).
2. Try [dCode](https://www.dcode.fr/) or [CyberChef](https://gchq.github.io/CyberChef/)'s "Magic" wand before writing custom code — many classic-cipher challenges are solved in seconds this way.
3. Check for encoding layered on top of encryption (base64/hex/rot13 wrapping the real ciphertext).

## Classic Ciphers

**Tools/Commands:**

* Caesar / ROT-N: brute-force all 25 shifts — `for i in range(26): print(shift(text, i))`
* Vigenère: recover key length via Kasiski examination / index of coincidence, then solve as repeating-key XOR against likely plaintext (`the`, `flag`)
* Substitution: frequency analysis, `quipqiup.com` for automated solving

## XOR

**Description:** Single-byte or repeating-key XOR is extremely common as an obfuscation layer.

**Tools/Commands:**

* Single-byte XOR brute force:

```python
ct = bytes.fromhex("...")
for k in range(256):
    pt = bytes(b ^ k for b in ct)
    if b'flag' in pt.lower():
        print(k, pt)
```

* Repeating-key XOR: guess key length via Hamming distance between blocks, then solve each column as single-byte XOR (classic CryptoPals approach)
* `xortool ciphertext.bin` — automates key-length guessing and brute force

## RSA

**Description:** By far the most common CTF crypto target — the vulnerability is almost always in *how* RSA was implemented, not in RSA itself.

**Check these in order:**

| Weakness | How to spot it | Tool |
| --- | --- | --- |
| Small `n` | `n` factors easily | `factordb.com`, `sympy.factorint(n)` |
| Common factor across multiple `n` | Two+ public keys given | `gcd(n1, n2)` — a shared prime breaks both |
| Small `e` (e.g. `e=3`) with no padding | Small `e`, small message | Direct `e`-th root: `gmpy2.iroot(c, e)` |
| Wiener's attack (small `d`) | Large `e`, hint about small private exponent | `RsaCtfTool.py --attack wiener` |
| Common modulus attack | Same `n`, different `e`, same message | Extended Euclidean algorithm on the two ciphertexts |
| Fermat factorization | `p` and `q` close together | `RsaCtfTool.py --attack fermat` |

**Go-to tool:** [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) — throws most known attacks at a given `n`/`e`/`c` automatically:

```
python3 RsaCtfTool.py --publickey key.pub --uncipherfile ciphertext
```

**Manual decrypt once `p`, `q` are known:**

```python
from Crypto.Util.number import inverse, long_to_bytes
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

## Hashing

**Description:** Identifying and cracking hashes.

**Tools/Commands:**

* Identify hash type: `hashid <hash>` or `hash-identifier`
* Crack against a wordlist: `hashcat -m <mode> hash.txt rockyou.txt` / `john --wordlist=rockyou.txt hash.txt`
* Length-extension attacks against unsalted `MD5(secret || data)` / `SHA1(secret || data)` constructions: `hashpump`

## AES / Block Ciphers

**Description:** Look for implementation mistakes — ECB mode, reused IVs/nonces, and padding oracles are the usual entry points, not breaking AES itself.

**Tools/Commands:**

* Detect ECB (repeated ciphertext blocks reveal repeated plaintext blocks — visible as patterns e.g. in an ECB-encrypted image):

```python
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
print(len(blocks) != len(set(blocks)))  # True => repeated block => likely ECB
```

* CBC padding oracle: [PadBuster](https://github.com/AonCyberLabs/PadBuster) or a custom script exploiting a "valid/invalid padding" oracle response
* Reused stream cipher/CTR nonce: XOR the two ciphertexts together to cancel the keystream and recover the XOR of the two plaintexts, then use crib-dragging

## Advanced Techniques

### Lattice Attacks

**Description:** when RSA leaks *partial* information — a few known bits of `p`, a truncated/stereotyped message, a small difference between primes — rather than being fully broken, lattice reduction recovers the rest. This is the standard toolset for RSA challenges beyond the basic weakness table above.

**Coppersmith's method:** finds small roots of a polynomial mod `N` in polynomial time when the root is below roughly `N^(1/deg)`, by building a lattice of shifted/scaled polynomials that share the root and extracting it from a short reduced basis vector. Classic applications:

* Partial key exposure — known high/low bits of `p` → recover the rest of `p`.
* Stereotyped/partial message exposure — `m = known_prefix || unknown_bits` → recover `m` from `c` without factoring `N`.

**LLL basis reduction:** the underlying primitive Coppersmith's method (and most lattice CTF attacks) reduces to — takes a lattice basis of long, non-orthogonal vectors and produces a reduced basis of short, nearly-orthogonal vectors in polynomial time. In practice: "build the right lattice, LLL-reduce it, read off a short vector."

**Tools:**

```python
# sagemath — built-in Coppersmith implementation
P.<x> = PolynomialRing(Zmod(n))
f = (x - known_high_bits).monic()
roots = f.small_roots(X=2^bound, beta=1)   # beta=1 for a full-N modulus
```

* [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)'s `--attack partial_p` and related lattice-backed modules automate the common partial-key cases.
* Standalone reference implementations ([defund/coppersmith](https://github.com/defund/coppersmith), rkm0959's public lattice write-ups/scripts) when Sage's default `small_roots()` doesn't converge — tuning `beta`/`epsilon`/lattice dimension is usually the actual hard part.

### ECC-Specific Attacks

**Invalid curve attack:** send a point that satisfies a *different*, weaker curve equation than the one the server expects (same modulus, different `a`/`b`) — many implementations never verify the point lies on the intended curve before scalar-multiplying it. If the attacker-chosen curve has smooth (small-factor) order, the server's response leaks the private key mod each small factor, recombined via CRT.

**Small subgroup confinement:** related — send a point of small order so the shared secret is confined to a small subgroup; without subgroup-membership validation, the small-order component of the private key/shared secret can be brute-forced from the exchange.

**ECDSA nonce reuse (weak curve/parameter reuse):** if the same nonce `k` signs two different messages under the same key, the private key is directly recoverable. Given signatures `(r, s1)` on hash `z1` and `(r, s2)` on `z2` (same `r` ⇒ same `k`), with curve order `n`:

```
k = (z1 - z2) / (s1 - s2)  mod n
d = (s1*k - z1) / r        mod n
```

```python
from Crypto.Util.number import inverse

k = ((z1 - z2) * inverse(s1 - s2, n)) % n
d = ((s1 * k - z1) * inverse(r, n)) % n
```

Detect by spotting a repeated `r` value across multiple signatures from the same key — that alone confirms nonce reuse before computing anything.

### PRNG Prediction

**Mersenne Twister (Python's `random`, many "custom PRNG" challenges):** the full internal state is recoverable from **624 consecutive 32-bit outputs** by untempering — inverting the fixed, invertible bit-shuffle applied to each raw state word before output. Once recovered, all future (and past) outputs are predictable.

```python
from randcrack import RandCrack
rc = RandCrack()
for output in outputs[:624]:
    rc.submit(output)
predicted_next = rc.predict_getrandbits(32)
```

[randcrack](https://github.com/tna0y/Python-random-cracker) automates untempering; do it by hand only for non-standard output widths or partially-leaked bits, where a z3/custom untemper is needed instead.

**LCG parameter recovery:** for `x_{n+1} = (a*x_n + c) mod m`, enough consecutive outputs recover unknown `a`, `c`, and even `m`:

* `m` known, `a`/`c` unknown — two consecutive outputs and basic algebra solve directly.
* `m` unknown — compute differences `t_i = x_{i+2} - x_{i+1} - (x_{i+1} - x_i)` (all ≡ 0 mod m); `m` falls out as the `gcd` of several such differences, recovering the modulus without knowing it up front.

### Padding Oracle (byte-by-byte CBC)

**Description:** given an oracle that reveals only whether decrypted CBC padding is valid, decrypt (and forge) arbitrary ciphertext without the key, one byte at a time, one block at a time.

**Algorithm — decrypting block `C[i]` using the preceding block `C[i-1]` as its effective IV:**

1. Replace `C[i-1]` with an attacker-controlled block `C'`. The real key still produces intermediate state `I = D(C[i])`; the plaintext byte the server checks is `P' = I XOR C'`.
2. Brute-force `C'[15]` (256 tries) until the oracle reports valid padding — this means `P'[15] = 0x01`, so `I[15] = C'[15] XOR 0x01`. (Handle the false-positive where genuine plaintext already ends `\x01\x01` by also varying byte 14 and re-checking.)
3. Fix `C'[15]` to force `P'[15] = 0x02`, then brute-force `C'[14]` until valid — reveals `I[14]`.
4. Repeat leftward across all 16 bytes, incrementing the target padding value each round (`0x03` … `0x10`).
5. Recover real plaintext: `P[i] = I XOR C[i-1]` — using the **original** preceding ciphertext block, not the modified `C'`.
6. Repeat per block. The same primitive lets you *encrypt* arbitrary plaintext (forge a valid ciphertext): choose `I` via the oracle and work backward, setting each `C'` byte to `I XOR desired_plaintext_byte`.

**Tools:** [PadBuster](https://github.com/AonCyberLabs/PadBuster) automates this against an HTTP oracle; for a custom protocol/raw TCP oracle, implement the loop directly — it's mechanical once the oracle's valid/invalid signal is confirmed.

### Timing Side-Channels

**Description:** a distinct class from padding oracles — any comparison that short-circuits (`token == expected` byte-by-byte, `strcmp` on a secret, `hmac.compare_digest` not being used) leaks information through response latency rather than an explicit oracle signal.

* Detect: send guesses correct for an increasing number of leading bytes and measure latency — a non-constant-time comparison returns marginally faster on a full mismatch than on a partial match extended one byte further.
* Statistical rigor matters more than for a padding oracle: take many samples per guess and compare distributions (median/trimmed mean), not single measurements, to beat network jitter.
* Fix/identify in review: naive `==`/`strcmp`/early-return loops on secrets are vulnerable; `hmac.compare_digest`, Go's `crypto/subtle.ConstantTimeCompare`, etc. are constant-time-safe — CTF challenges deliberately use the naive form to make this exploitable.

## Useful references

* [CyberChef](https://gchq.github.io/CyberChef/) — encode/decode/hash everything
* [CryptoHack](https://cryptohack.org/) — great for building crypto CTF intuition
* [factordb.com](http://factordb.com/) — precomputed factorizations for known composites
