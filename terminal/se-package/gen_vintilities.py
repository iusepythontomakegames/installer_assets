#!/usr/bin/env python3
"""Generate vintilities.opp (O++) from line lists, with exact fwrite lengths."""

REQ_PATH = "/etc/vintilities.sysreq"
REQ_FLAGS = 769   # VFS_O_WRONLY|VFS_O_CREAT|VFS_O_TRUNC (0x301)

banner = [
    "vintilities — SCFB OS organizational router management console",
    "NOTICE: vintilities is for organizations managing their OWN",
    "WiFi networks (traffic, devices, deauth containment, HTTPS",
    "inspection via org-deployed CA). It is NOT for malicious use.",
    "Use only on networks you administer, with proper authorization.",
]

request = [
    "SYSREQ v1 — SCFB OS system change request",
    "id: vintilities-terminal-command",
    "from: vintilities.se (SEPERM: root + fs + net, requested at launch)",
    "change: edit the terminalL command table (apps/terminalL.c)",
    "add terminal command: vintilities",
    "binding: typing 'vintilities' launches /usr/bin/vintilities.se,",
    "         then terminalL opens the vintilities shell (interactive,",
    "         same host pattern as bobs/tobs: shell_request style mode)",
    "shell: vintilities — organizational router management",
    "scope: organization-owned WiFi only, with admin consent",
    "commands:",
    "  help            — command list + acceptable-use warning",
    "  warning         — show the org-use warning",
    "  devices         — list devices on the organization AP",
    "  traffic         — manage traffic (shape / limit / prioritize)",
    "  deauth          — manage deauth signals (rogue/unauthorized",
    "                    device containment on org APs only)",
    "  deauth list     — list pending/active deauth targets",
    "  https           — decrypt HTTPS via org-deployed CA",
    "  https read     — read contents of captured HTTPS sessions",
    "  https write    — read-write contents of org-managed sessions",
    "  route           — routing table (list / add / delete)",
    "  status         — router/AP status",
    "  exit            — leave the vintilities shell",
    "gates: root required for every command; SOD audit log entry per",
    "       command; org-use warning must print on shell entry",
    "requested: apply at the next terminalL build (src10)",
]

outro = [
    "request filed: /etc/vintilities.sysreq (id: vintilities-terminal-command)",
    "SOD chain of custody: request recorded in the SOD audit log",
    "when applied, typing 'vintilities' in terminalL opens the shell",
    "until then this request sits pending SOD review (root-verified)",
    "vintilities: remember — organizations only, never malicious use.",
]

lines = []
lines.append('// vintilities.opp — SEFMT 3.0, O++ (tools/ocomp-se3.py)')
lines.append('// Registers a system change request: add the terminal')
lines.append('// command "vintilities" so typing it opens the vintilities')
lines.append('// shell (organizational router management). Built with a')
lines.append('// SEPERM manifest: root + fs + net (requested at launch).')
lines.append('')
lines.append('function main() {')
for l in banner:
    lines.append(f'    write("{l}");')
lines.append(f'    int fd = fopen("{REQ_PATH}", {REQ_FLAGS});')
lines.append('    if (fd < 0) then {')
lines.append(f'        write("cannot open {REQ_PATH} — FS permission denied?");')
lines.append('    }')
lines.append('    else {')
for l in request:
    esc = l.replace('\\', '\\\\').replace('"', '\\"')
    lines.append(f'        fwrite(fd, "{esc}\\n", {len(l) + 1});')
lines.append('        fclose(fd);')
lines.append(f'        write("filed system change request: {REQ_PATH}");')
lines.append('    }')
for l in outro:
    lines.append(f'    write("{l}");')
lines.append('}')

body = "\n".join(lines).replace("\u2014", "-")
open("vintilities.opp", "w").write(body + "\n")
print("vintilities.opp written,", len(lines), "source lines")
