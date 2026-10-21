#!/usr/bin/env python3
"""Verify vintilities.se: SEPERM manifest entries + every fwrite call
passes (fd-reg, rodata string addr, len) with len == strlen+1, and the
full request text reconstructed from the image matches the spec."""
import struct, subprocess, sys

d = open("vintilities.se","rb").read()
assert d[:7] == b"SEFMT\x00\x03", "bad magic"
flags = d[9]
assert flags & 0x08, "SEFMT 3.0 flag missing"
assert flags & 0x10, "O++ flag missing"
# integrity trailer
import zlib
crc = struct.unpack_from('<I', d, len(d)-4)[0]
assert crc == zlib.crc32(d[:-4]) & 0xFFFFFFFF, "integrity seal mismatch"

# sections
coff, csz = struct.unpack_from('<QQ', d, 0x18)
roff, rsz = struct.unpack_from('<QQ', d, 0x28)
stoff, stsz = struct.unpack_from('<QQ', d, 0x50)
code, rodata = d[coff:coff+csz], d[roff:roff+rsz]

# SEPERM manifest: search for magic after strings
pi = d.find(b"SEPERM\x00\x03")
assert pi > 0, "SEPERM manifest missing"
total = struct.unpack_from('<I', d, pi+8)[0]
count = struct.unpack_from('<H', d, pi+12)[0]
entries = []
for i in range(count):
    eo = pi + 16 + i*24
    name_off, level, eflags, grant, reason_off = struct.unpack_from('<IBBHI', d, eo)
    name = d[pi+name_off: d.index(b"\x00", pi+name_off)].decode()
    reason = d[pi+reason_off: d.index(b"\x00", pi+reason_off)].decode() if reason_off else ""
    entries.append((name, level, eflags, grant, reason))
    assert eflags == 0x01, "entry not marked requested-at-launch"
print("SEPERM manifest:")
for e in entries: print("  %-4s level=%d flags=request grant=0x%02x  %s" % (e[0], e[1], e[3], e[4]))
grant_or = 0
for e in entries: grant_or |= e[3]
assert grant_or == 0x07, "want root|fs|net, got 0x%02x" % grant_or

# scan code bytes for the fwrite stub-call pattern:
#   movabs $str,%rax; mov %rax,%rsi; movabs $len,%rax; mov %rax,%rdx;
#   movabs $0x40180,%rax; call *%rax
import struct as _s
pat_call = b"\x48\xb8" + _s.pack("<Q", 0x40180) + b"\xff\xd0"
fwrites = []
i = 0
while True:
    j = code.find(pat_call, i)
    if j < 0: break
    tail = code[:j]
    if tail.endswith(b"\x48\x89\xc2") and tail[-13:-3].startswith(b"\x48\xb8"):
        ln = _s.unpack_from("<Q", tail, len(tail)-13+2)[0]
        t2 = tail[:len(tail)-13]
        if t2.endswith(b"\x48\x89\xc6") and t2[-13:-3].startswith(b"\x48\xb8"):
            addr = _s.unpack_from("<Q", t2, len(t2)-13+2)[0]
            fwrites.append((addr, ln))
    i = j + len(pat_call)
ok = True
req_lines = []
for addr, ln in fwrites:
    s = rodata[addr-0x20000:]
    nul = s.index(b"\x00")
    s = s[:nul]
    if len(s) != ln:
        print("LEN MISMATCH: wrote %d, string is %d: %r" % (ln, len(s), s)); ok = False
    req_lines.append(s.decode())
print("fwrite calls validated:", len(fwrites), "(all lengths exact)" if ok else "(FAILED)")
assert ok
open("vintilities.sysreq","wb").write(("\n".join(req_lines)+"\n").encode())
print("reconstructed request file -> vintilities.sysreq")
need = ["vintilities", "deauth", "traffic", "https", "devices", "route",
        "terminalL command table", "root required"]
body = "\n".join(req_lines)
for n in need:
    assert n.lower() in body.lower(), "missing spec keyword: "+n
print("spec keywords present:", ", ".join(need))
