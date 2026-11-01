#!/usr/bin/env python3
"""Verify partman.se: SEFMT 3.1 header + CRC, SEPERM v3.1 manifest (tiers and
grant bits), the getuid/open/write stub usage, and that every fwrite triplet
is (fd, rodata addr, strlen+1) so the sysreq text reconstructs exactly."""
import struct, zlib, sys

PATH = "partman.se"   # repo copy: verify the committed image
d = open(PATH, "rb").read()
fail = 0
def check(cond, msg):
    global fail
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond: fail += 1

check(d[:7] == b"SEFMT\x00\x03", "magic SEFMT 3.0")
check(bool(d[9] & 0x08), "SEFMT 3.0 flag")
check(bool(d[9] & 0x10), "O++ language flag")
crc = struct.unpack_from("<I", d, len(d) - 4)[0]
check(crc == zlib.crc32(d[:-4]) & 0xFFFFFFFF, "SEFMT 3.1 integrity seal (CRC32)")

ver = d[6]   # "SEFMT\0\3": version lives in the magic itself
coff, csz = struct.unpack_from("<QQ", d, 0x18)
roff, rsz = struct.unpack_from("<QQ", d, 0x28)
doff, dsz = struct.unpack_from("<QQ", d, 0x38)
soff, ssz = struct.unpack_from("<QQ", d, 0x50)
toff, tsz = struct.unpack_from("<QQ", d, 0x58)
check(ver == 3, "image version 3")
check(ssz >= 0x240, "stubs section carries the unix slots (>=0x240, getuid)")

code = d[coff:coff + csz]
rodata = d[roff:roff + rsz]

# ── SEPERM manifest ────────────────────────────────────────────────────────
pi = d.find(b"SEPERM\x00\x03")
check(pi > 0, "SEPERM v3.1 manifest present")
total = struct.unpack_from("<I", d, pi + 8)[0]
count = struct.unpack_from("<H", d, pi + 12)[0]
check(16 + count * 24 <= total <= len(d) - pi, "manifest size/count consistent")
entries = []
for i in range(count):
    eo = pi + 16 + i * 24
    name_off, level, eflags, grant, reason_off = struct.unpack_from("<IBBHI", d, eo)
    name = d[pi + name_off: d.index(b"\x00", pi + name_off)].decode()
    reason = d[pi + reason_off: d.index(b"\x00", pi + reason_off)].decode() if reason_off else ""
    entries.append((name, level, eflags, grant, reason))

print("     SEPERM entries:")
for n, lv, fl, g, r in entries:
    print("       %-6s tier=%d flags=0x%02x grant=0x%02x  %s" % (n, lv, fl, g, r))
check(all(e[2] == 0x01 for e in entries), "every entry requests at launch")
grant_or = 0
for e in entries: grant_or |= e[3]
check(grant_or == 0x43, "grant = ROOT|FS|PART (0x43), got 0x%02x" % grant_or)
check(any(e[0] == "part" and e[1] == 2 for e in entries),
      "partition entry is tier 2 (partition-level)")
check(all(e[3] & ~0x7F == 0 for e in entries), "no grant bit outside the known mask")

# ── symbol table: the stubs the image actually calls ───────────────────────
want = {b"__stub_write_str", b"__stub_fopen", b"__stub_fwrite",
        b"__stub_fclose", b"__stub_getuid"}
found = set()
for name in want:
    if name in d[toff:toff + tsz]:
        found.add(name)
check(found == want, "symbol table lists %s" % ", ".join(sorted(n.decode() for n in want)))
check(b"/etc/partman.sysreq" in rodata, "sysreq path in rodata")
check(b"PARTEXEC" in rodata, "PARTEXEC consent text in rodata")
check(b"partition-level" in rodata, "partition-level wording in rodata")

# ── fwrite triplets: movabs $str; mov %rax,%rsi; movabs $len; mov %rax,%rdx;
#    movabs $0x40180; call *%rax   (0x40180 = fwrite stub slot) ─────────────
pat_call = b"\x48\xb8" + struct.pack("<Q", 0x40180) + b"\xff\xd0"
lines, i = [], 0
while True:
    j = code.find(pat_call, i)
    if j < 0: break
    tail = code[:j]
    if tail.endswith(b"\x48\x89\xc2") and tail[-13:-3].startswith(b"\x48\xb8"):
        ln = struct.unpack_from("<Q", tail, len(tail) - 11)[0]
        t2 = tail[:len(tail) - 13]
        if t2.endswith(b"\x48\x89\xc6") and t2[-13:-3].startswith(b"\x48\xb8"):
            addr = struct.unpack_from("<Q", t2, len(t2) - 11)[0]
            lines.append((addr, ln))
    i = j + len(pat_call)

check(len(lines) == 25, "25 fwrite calls found, one per request line (got %d)" % len(lines))
# each call is fwrite(fd, "<line>\n", len("<line>")+1): the trailing byte is
# the newline, and the kernel's write path takes a length, not a NUL.
bad = []
text = []
for addr, ln in lines:
    off = addr - 0x20000
    s = rodata[off:off + ln]
    text.append(s)
    if len(s) != ln or not s.endswith(b"\n") or b"\x00" in s:
        bad.append((hex(addr), ln, s[:40]))
check(not bad, "every fwrite writes exactly (line + newline), one byte past the text")
if bad:
    for b in bad: print("     bad triplet:", b)

req = b"".join(text).decode()
check(req.startswith("SYSREQ v1 - SCFB OS system change request\n"), "request starts with SYSREQ v1")
for must in ["id: partman-terminal-command",
             "syscall: SC_PARTCTL, permission PERM_PART (0x40, tier 2)",
             "device: /dev/ata0 - first ATA disk, MBR, 4 primary slots",
             "  root N [PATH]  - set/show the root directory of slot N"]:
    check(must in req, "request contains %r" % must)

print()
print("SEPERM grant 0x%02x (root|fs|part) tier2, %d lines of sysreq text"
      % (grant_or, len(lines)))
print("PASS" if fail == 0 else "FAIL (%d)" % fail)
sys.exit(1 if fail else 0)
