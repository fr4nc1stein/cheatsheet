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

## Advanced Techniques

### Symbolic Execution with angr

**Description:** reach for [angr](https://angr.io/) when a "check" function is buried behind many conditional branches, opaque optimized code, or an unclear input length — let an SMT solver find an input that reaches the success state instead of tracing the logic by hand. If you can already see the exact transform (XOR, arithmetic, table lookup), reversing it directly in Python is still faster; angr earns its cost on genuinely branchy constraint problems (license-key checks, obfuscated crackmes).

**Worked example structure:**

```python
import angr, claripy

proj = angr.Project('./crackme', auto_load_libs=False)

flag_len = 20
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.full_init_state(args=['./crackme'], stdin=flag)

# constrain to printable input to keep the search space sane
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
               avoid=lambda s: b'Wrong' in s.posix.dumps(1))

if simgr.found:
    found = simgr.found[0]
    print(found.posix.dumps(0))
```

Common pitfalls: state explosion on loops (bound exploration with `avoid`/`LoopSeer`), unmodeled library calls (`proj.hook_symbol` to stub them), and getting the input harness wrong (stdin vs. argv vs. a custom `read()`) — a wrong harness reads as "unsat" and looks like a dead end when it's actually a setup bug.

### VM-Based Obfuscation / Control-Flow Flattening

**Description:** custom bytecode VMs and flattened control flow are the standard defense against straightforward decompilation once a challenge moves past "just reverse the binary."

**Recognizing a custom VM:** look for a single large loop containing a `switch`/jump-table dispatch on a byte pulled from a buffer — structurally `while (1) { op = bytecode[pc++]; switch(op) { case 0x01: ...; } }`. This **dispatch loop + opcode table** shape is the signature; a large function with dozens of simple `switch` cases each doing trivial stack/register operations is a VM interpreter, not "real" application logic.

**Deobfuscation strategy:**

1. Extract the opcode table — enumerate every `case` and the operation it performs on the VM's internal state (stack, registers, memory).
2. Rebuild each opcode's semantics in your own notation (`ADD`, `PUSH`, `JMP`, `CMP`, ...) — treat this like reversing an unfamiliar ISA, not reading a program.
3. Dump the bytecode itself and analyze *that* using your rebuilt semantics, rather than continuing to read the interpreter's native-code disassembly.
4. Consider **emulating instead of fully reversing**: once the VM's calling convention and instruction encoding are understood well enough to drive it, run the interpreter's native loop directly against controlled inputs with [Unicorn Engine](https://www.unicorn-engine.org/), treating it as a black box — often faster than reimplementing the VM's full semantics when the goal is solving, not documenting.

**Control-flow flattening:** the real CFG collapses into a single dispatcher loop plus a "state variable" selecting the next block (`switch(state) { case 1: ...; state = 4; break; }`). Decompiler output is close to useless as-is; deflattening (community Ghidra/IDA scripts that trace the state variable's assignments across blocks) or manual tracing of state transitions recovers the original control flow.

### Firmware / Embedded RE

**Tools/Commands:**

* Recursive automated extraction:

```
binwalk -Me firmware.bin
```

(`-M` matryoshka/recursive mode, `-e` extract — pulls filesystems, kernels, bootloaders out of arbitrarily nested blobs.)

* Emulate an extracted binary/filesystem of a foreign architecture:

```
qemu-user -L /path/to/extracted/rootfs ./extracted/rootfs/usr/bin/target_binary
qemu-system-arm -M virt -kernel zImage -drive file=rootfs.img -append "console=ttyAMA0" -nographic
```

`qemu-user-static` + `chroot` into the extracted rootfs is usually the fastest path when you just need to run/`strace` one binary against its native shared libs.

* Common embedded flag locations: bootloader (U-Boot) environment strings — `strings` the bootloader partition for `bootargs`/`bootcmd`; NVRAM/config partitions, usually flagged by `binwalk` as a separate `squashfs`/`jffs2`/raw region; default credentials or debug endpoints left in a config partition.
* [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit) as a fallback extraction/repack toolchain when `binwalk` mis-identifies a filesystem.
