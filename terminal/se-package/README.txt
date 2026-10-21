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
