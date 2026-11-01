#!/usr/bin/env python3
"""Generate partman.opp (O++, SEFMT 3.0) from line lists, with exact fwrite
lengths so the compiler's (fd, string, len) triplets stay honest."""

# repo copy: run from the se-package directory, writes partman.opp here
OUT_PATH = "partman.opp"

REQ_PATH = "/etc/partman.sysreq"
REQ_FLAGS = 769          # VFS_O_WRONLY|VFS_O_CREAT|VFS_O_TRUNC (0x301)

banner = [
    "partman 1.0 - partition-level storage management (SCFB OS)",
    "==========================================================",
    "",
    "PARTEXEC: this image requests PARTITION-LEVEL EXECUTION RIGHTS.",
    "They are a separate tier from root (SEPERM level 2) and cover:",
    "  create  - a new primary partition in a free extent",
    "  delete  - free a slot, and the partition's data goes with it",
    "  resize  - an exact size in MB, grown or shrunk",
    "  alloc   - claim the free tail of an existing partition",
    "  format  - rewrite the SCFB volume header (re-format)",
    "  root    - assign the partition's root directory",
    "",
    "read-only until a command is given: this image only asks.",
    "gate: the kernel validates the SEPERM manifest and refuses the image",
    "unless root + fs + part (tier 2) are granted, so seeing this text",
    "means the request was accepted for this launch.",
]

gate_ok = [
    "PARTEXEC accepted: uid 0, partition-level tier active for this task.",
]
gate_no = [
    "PARTEXEC refused: this task is not root, so nothing is written.",
    "re-run it as root (sudo run /usr/bin/partman.se).",
]

request = [
    "SYSREQ v1 - SCFB OS system change request",
    "id: partman-terminal-command",
    "from: partman.se (SEPERM: root 1:0x01 + fs 1:0x02 + part 2:0x40)",
    "change: edit the terminalL command table (apps/terminalL.c)",
    "add terminal command: partman",
    "binding: typing 'partman' opens the consent page and the table;",
    "         'partman accept' accepts PARTEXEC for the session",
    "engine: kernel/part.c + kernel/part.h (MBR read-modify-write)",
    "syscall: SC_PARTCTL, permission PERM_PART (0x40, tier 2)",
    "device: /dev/ata0 - first ATA disk, MBR, 4 primary slots",
    "writes: sector 0 of the disk (MBR) and LBA 0 of each partition",
    "        touched (SCFB volume header: label, fs, root directory)",
    "operations:",
    "  list           - table, per-partition roots, largest free extent",
    "  info N         - geometry + volume header of slot N",
    "  create NAME SIZE [fs] - new partition, root /mnt/NAME",
    "  delete N       - free slot N (data is not recovered)",
    "  resize N SIZE  - set slot N to SIZE MB",
    "  alloc [N]      - free extents, or claim slot N's free tail",
    "  format N [fs]  - rewrite the volume header (scfbfs|raw|fat32|swap)",
    "  root N [PATH]  - set/show the root directory of slot N",
    "persistence: the MBR is the source of truth for geometry, the volume",
    "             header for label/fs/root; both survive a reboot",
    "gates: PARTEXEC consent at the shell + PERM_PART at the kernel;",
    "       an unaccepted or unelevated shell gets -EPERM and no write",
]

outro_ok = [
    "request filed: /etc/partman.sysreq (id: partman-terminal-command)",
    "partition table: /dev/ata0, MBR, 4 primary slots, 1 MiB aligned",
    "use: partman            consent page + current table",
    "     partman accept     accept PARTEXEC for this session",
    "     partman list | info N | create NAME SIZE [fs]",
    "     partman delete N | resize N SIZE | alloc [N]",
    "     partman format N [fs] | root N [PATH]",
]


def esc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def main():
    L = []
    L.append('// partman.opp - SEFMT 3.0, O++ (tools/ocomp-se3.py)')
    L.append('// Partition-level storage management front-end for SCFB OS.')
    L.append('// SEPERM v3.1 manifest: root(0x01) + fs(0x02) + part(0x40 at tier 2),')
    L.append('// requested at launch. Tier 2 is the partition-level grant: the kernel')
    L.append('// will not launch this image unless a task may rewrite disk geometry,')
    L.append('// so the request is answered before the first instruction runs.')
    L.append('//')
    L.append('// The engine lives in kernel/part.c (MBR read-modify-write); the shell')
    L.append('// face is terminalL `partman`. This image is the requester + consent')
    L.append('// page, the same pattern as vintilities.se.')
    L.append('')
    L.append('function main() {')
    for l in banner:
        L.append('    write("%s\\n");' % esc(l))
    L.append('')
    L.append('    int uid = getuid();')
    L.append('    if (uid = 0) then {')
    for l in gate_ok:
        L.append('        write("%s\\n");' % esc(l))
    L.append('    }')
    L.append('    else {')
    for l in gate_no:
        L.append('        write("%s\\n");' % esc(l))
    L.append('    }')
    L.append('')
    L.append('    int fd = fopen("%s", %d);' % (REQ_PATH, REQ_FLAGS))
    L.append('    if (fd < 0) then {')
    L.append('        write("cannot open %s - FS permission denied?\\n");' % REQ_PATH)
    L.append('    }')
    L.append('    else {')
    for l in request:
        L.append('        fwrite(fd, "%s\\n", %d);' % (esc(l), len(l) + 1))
    L.append('        fclose(fd);')
    L.append('        write("filed: %s\\n");' % REQ_PATH)
    L.append('    }')
    L.append('')
    for l in outro_ok:
        L.append('    write("%s\\n");' % esc(l))
    L.append('}')

    body = "\n".join(L) + "\n"
    open(OUT_PATH, "w").write(body)
    print("partman.opp written: %d lines, %d bytes" % (len(L), len(body)))


if __name__ == "__main__":
    main()
