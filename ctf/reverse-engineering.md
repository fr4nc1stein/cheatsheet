# Reverse Engineering

## Triage

1. **Identify file type & protections.**\
   **Tools/Commands:**
   * `file <binary>`
   * `checksec <binary>`
   * `strings <binary> | grep -iE "flag|key|password"`
2. **Check for packing/obfuscation.**\
   **Tools/Commands:**
   * `die <binary>` (Detect It Easy) — identifies packers/compilers
   * High entropy + few readable strings + a small import table is a strong sign of packing (e.g. UPX)
   * Unpack UPX: `upx -d <binary>`

## Static Analysis

**Tools:**

* [Ghidra](https://ghidra-sre.org/) — free, full decompiler, great default choice
* [IDA Free](https://hex-rays.com/ida-free/) — best-in-class disassembler, free tier lacks 64-bit decompiler
* [Binary Ninja](https://binary.ninja/) — good UI, scriptable
* `objdump -d -M intel <binary>` — quick disassembly without a GUI

**Workflow:**

1. Look at `main`, then follow calls to anything named suspiciously (`check_flag`, `validate`, `encrypt`).
2. Rename variables/functions as you understand them (Ghidra: `L` key) — keeps the decompiled output readable as you go.
3. For a "check the input character by character" pattern, extract the comparison values directly rather than tracing the algorithm by hand.

## Dynamic Analysis

**Tools/Commands:**

* `gdb ./binary` with [pwndbg](https://github.com/pwndbg/pwndbg)/[GEF](https://github.com/hugsy/gef) — breakpoint on the check function, inspect registers/memory at the comparison
* `ltrace ./binary` / `strace ./binary` — library and syscall trace, fast way to see what a binary touches
* `x64dbg` (Windows) — GUI debugger, good for PE binaries
* Frida for hooking functions at runtime without a full debugger session:

```bash
frida-trace -i "strcmp" ./binary
```

## .NET binaries

**Tools/Commands:**

* [dnSpy](https://github.com/dnSpy/dnSpy) / [ILSpy](https://github.com/icsharpcode/ILSpy) — decompile to near-original C#, can edit and re-save

## Java (JAR / .class)

**Tools/Commands:**

* [JD-GUI](https://java-decompiler.github.io/) / [CFR](https://www.benf.org/other/cfr/) — decompile `.class`/`.jar` to Java source
* `javap -c ClassFile.class` — raw bytecode without full decompilation

## Android (APK)

**Tools/Commands:**

* `apktool d app.apk` — unpack resources + smali
* `jadx-gui app.apk` — decompile to readable Java
* `adb logcat` while running the app on an emulator, to observe runtime behavior

## Anti-debugging tricks to watch for

* `ptrace(PTRACE_TRACEME, ...)` self-trace to detect an attached debugger — patch the call or use `LD_PRELOAD` to stub it out
* Timing checks around a code block (`rdtsc`) to detect single-stepping
* `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` on Windows

## Scripting the solve

Once the algorithm is understood, it's usually faster to reimplement the check (or its inverse) in Python than to keep single-stepping:

```python
target = [0x1a, 0x2f, 0x03, ...]  # extracted from the binary
flag = ''.join(chr(b ^ 0x5a) for b in target)  # example: reverse an XOR
print(flag)
```

Consider [z3](https://github.com/Z3Prover/z3) when the check is a set of constraints (common in "crackme" style challenges) rather than a simple reversible transform:

```python
from z3 import *
s = Solver()
chars = [BitVec(f'c{i}', 8) for i in range(N)]
# add constraints derived from the binary's checks...
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in chars))
```
