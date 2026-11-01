vintilities.se — SCFB OS system change request program (src9-era)
==================================================================

WHAT IT IS
  vintilities.se is a SEFMT 3.0 / O++ image (SEPERM 3.1 manifest,
  CRC-sealed) that REQUESTS a system change: register a new terminalL
  command, "vintilities", which opens the vintilities shell - an
  interactive organizational router management console.

  On launch (root-gated: `sudo run /usr/bin/vintilities.se`) it:
    1. prints the acceptable-use warning (organizations managing
       their OWN WiFi only - traffic, devices, deauth containment,
       HTTPS inspection via an org-deployed CA. NOT for malicious use)
    2. files the change request at /etc/vintilities.sysreq
    3. the request specifies the exact terminalL command-table edit
       and the full vintilities shell command spec (traffic, deauth,
       devices, https read/write, route, status, help, exit)

SEPERM MANIFEST (parsed by kernel/se.c se_perm_parse at exec)
  root  level=1 request grant=0x01  (router management commands)
  fs    level=0 request grant=0x02  (write the request to /etc)
  net   level=0 request grant=0x04  (router manipulation features)

FILES
  vintilities.opp        O++ source
  vintilities.se          compiled image (place in initramfs/usr/bin/)
  vintilities.sysreq      the request file it writes (exact contents)
  gen_vintilities.py      generator (computes exact fwrite byte lengths)
  verify_vintilities.py  validator: CRC seal, manifest, all 27 fwrite
                         lengths checked against rodata; spec keywords

BUILD
  python3 tools/ocomp-se3.py vintilities.opp \
    --perm "root:1:0x01:vintilities shell needs root for router management commands" \
    --perm "fs:0:0x02:write the system change request to /etc" \
    --perm "net:0:0x04:router manipulation (traffic, deauth, devices, routing)" \
    -o vintilities.se
  python3 tools/ocomp-se3.py vintilities.se --check

STATUS
  The .se is installed into the src9 tree at initramfs/usr/bin/
  vintilities.se. The request itself (the terminalL command-table edit
  + interactive shell mode, bobs/tobs-style) is the system change; it
  applies in the terminalL build after SOD review.


==========================================================================
partman.se - SCFB OS partition-level storage management (src11)
==========================================================================

WHAT IT IS
  partman.se is a SEFMT 3.0 / O++ image (SEPERM 3.1 manifest,
  CRC-sealed) that manages MBR partitions on the first ATA disk:
  create, delete, resize, re-format, claim free storage, and give a
  partition a root directory. The image never touches a sector itself.

  It asks for a permission tier of its own first. On launch
  (root-gated: bare-metal shell or `sudo run PATH`) it:
    1. prints what PARTITION-LEVEL EXECUTION RIGHTS cover and which
       sectors they reach (sector 0 = MBR, plus LBA 0 of each
       partition touched for the SCFB volume header)
    2. files that request at /etc/partman.sysreq
    3. prints the command set; it is read-only until a command runs

  In the shell the same page comes from the `partman` command, and
  nothing executes until the user types `partman accept`.

  GATES (three, all real):
    shell    `partman` shows the consent page, `partman accept`
             grants it for that terminal session
    loader   kernel/syscall.c refuses to launch an image declaring
             0x40 unless the launch is elevated; the tier is never
             inherited from the hosting task's PERM_ALL, so a
             sandboxed `run` gets -EPERM and no write
    kernel   SC_PARTCTL is registered with PERM_PART and re-checks
             the caller on every call

SEPERM MANIFEST (parsed by kernel/se.c se_perm_parse at exec)
  root  level=1 request grant=0x01  (privileged storage maintenance)
  fs    level=1 request grant=0x02  (write /etc/partman.sysreq, mkdir
                                     the partition root directories)
  part  level=2 request grant=0x40  (rewrite the MBR + volume headers)
  total grant 0x43 - requires a src11 kernel (PERM_PART, SC_PARTCTL).
  A src10 kernel has no 0x40 and refuses the launch, which is the
  point: the request is served by the OS, not assumed by the image.

COMMANDS
  partman                        consent page + current table
  partman accept                 accept PARTEXEC for this session
  partman list                   table, roots, largest free extent
  partman info N                 geometry + volume header of slot N
  partman create NAME SIZE [fs]  new partition, root /mnt/NAME
  partman delete N               free slot N (data goes with it)
  partman resize N SIZE          exact size in MB, grown or shrunk
  partman alloc [N]              free extents, or claim slot N's tail
  partman format N [fs]          rewrite the volume header
  partman root N [PATH]          set/show the root directory of slot N

FILES
  partman.opp            O++ source (80 lines)
  partman.se             compiled image (place in initramfs/usr/bin/)
  partman.sysreq         the request file it writes (exact contents)
  gen_partman.py         generator (computes exact fwrite byte lengths,
                         writes partman.opp beside it)
  verify_partman.py      validator: SEFMT magic, CRC seal, section
                         geometry, all 25 fwrite lengths against
                         rodata, SEPERM bits, stub slots

BUILD (from a SCB OS source tree)
  python3 tools/ocomp-se3.py partman.opp -o partman.se \
    --perm "root:1:0x01:root-level privileges for the partition manager" \
    --perm "fs:1:0x02:write /etc/partman.sysreq and the root directories" \
    --perm "part:2:0x40:partition-level: rewrite the MBR and volume headers"
  python3 verify_partman.py

STATUS
  The .se is installed into the src11 tree at initramfs/usr/bin/
  partman.se. The request it files (the terminalL `partman` command,
  kernel/part.c MBR engine, SC_PARTCTL, PERM_PART 0x40) is applied in
  src11 and verified in QEMU: create/delete/resize/alloc/format/root,
  plus a cold power-cycle that reads the table back from disk.
