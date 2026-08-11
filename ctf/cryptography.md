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

**Go-to tool:** [RsaCtfTool](https://github.com/Ph3nOx/RsaCtfTool) — throws most known attacks at a given `n`/`e`/`c` automatically:

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

## Useful references

* [CyberChef](https://gchq.github.io/CyberChef/) — encode/decode/hash everything
* [CryptoHack](https://cryptohack.org/) — great for building crypto CTF intuition
* [factordb.com](http://factordb.com/) — precomputed factorizations for known composites
