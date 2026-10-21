#include "vint.h"
#include "../fs/ramfs.h"
#include "../drivers/net/net.h"
#include "../drivers/net/http.h"
#include "../drivers/wifi.h"
#include "../kernel/heap.h"
#include "../kernel/sod.h"
#include "../lib/string.h"
#include <stdarg.h>

/* vintilities — organizational router management shell.
 *
 * Management-plane tables live in VintState. Where the kernel has a
 * real path (WiFi AP scan, NIC/IP status, the kernel TLS 1.3 stack)
 * the shell uses it; management actions that need AP-side enforcement
 * (deauth containment, shaping, routes) sit in a reviewed queue and
 * are honestly labeled as such. Every command is appended to the SOD
 * audit log (kernel/sod.c chain of custody). */

static void vint_emit(VintState *vs, const char *line) {
    if (vs->output) vs->output(vs->output_context, line);
}

static void vint_emitf(VintState *vs, const char *fmt, ...) {
    char line[192];
    va_list ap;
    va_start(ap, fmt);
    k_vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    (void)vs;
    vint_emit(vs, line);
}

static void vint_audit(const char *what) {
    char line[128];
    k_snprintf(line, sizeof(line), "vintilities: %s", what);
    sod_audit_line(line);
}

static void vint_show_warning(VintState *vs) {
    vint_emit(vs, "WARNING: vintilities is an organizational router");
    vint_emit(vs, "management tool. It is NOT meant for malicious use.");
    vint_emit(vs, "Use it only on WiFi networks your organization owns");
    vint_emit(vs, "and administers, with proper authorization.");
    vs->warning_shown = 1;
}

/* ── devices ─────────────────────────────────────────────────────── */

static void vint_cmd_devices(VintState *vs) {
    vint_emit(vs, "device inventory (organization AP)");
    char line[128];
    k_snprintf(line, sizeof(line), "%-18s %-16s %-24s %s",
               "MAC", "IP", "LABEL", "FLAG");
    vint_emit(vs, line);
    int shown = 0;
    for (int i = 0; i < vs->device_count; i++) {
        k_snprintf(line, sizeof(line), "%-18s %-16s %-24s %s",
                   vs->devices[i].mac, vs->devices[i].ip,
                   vs->devices[i].label,
                   vs->devices[i].rogue ? "ROGUE" : "ok");
        vint_emit(vs, line);
        shown++;
    }
    /* real radio state: whatever the kernel WiFi layer sees */
    static wifi_ap_t aps[16];
    int n = wifi_scan_aps(aps, 16);
    for (int i = 0; i < n; i++) {
        char mac[18];
        k_snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                   aps[i].bssid[0], aps[i].bssid[1], aps[i].bssid[2],
                   aps[i].bssid[3], aps[i].bssid[4], aps[i].bssid[5]);
        char ssidtag[40];
        k_snprintf(ssidtag, sizeof(ssidtag), "AP %s", aps[i].ssid);
        k_snprintf(line, sizeof(line), "%-18s %-16s %-24s rssi %d dBm",
                   mac, "(ap)", ssidtag, (int)aps[i].rssi);
        vint_emit(vs, line);
        shown++;
    }
    if (!shown) vint_emit(vs, "no devices known (AP scan empty)");
    vint_emit(vs, "add devices: devices add <mac> <ip> <label>");
    vint_audit("devices list");
}

static int vint_find_slot(const char *list_mac, const char *mac) {
    return k_streq(list_mac, mac);
}

static void vint_cmd_devices_add(VintState *vs,
                                 const char *mac, const char *ip,
                                 const char *label) {
    if (vs->device_count >= VINT_MAX_DEVICES) {
        vint_emit(vs, "devices: inventory full");
        return;
    }
    vint_device_t *d = &vs->devices[vs->device_count++];
    k_strcpy(d->mac, mac, sizeof(d->mac));
    k_strcpy(d->ip, ip, sizeof(d->ip));
    k_strcpy(d->label, label, sizeof(d->label));
    d->rogue = 0;
    char what[96];
    k_snprintf(what, sizeof(what), "devices add %s (%s)", mac, label);
    vint_audit(what);
    vint_emitf(vs, "device registered: %s (%s)", mac, label);
}

/* ── deauth (rogue containment on organization APs only) ─────────── */

static void vint_cmd_deauth(VintState *vs, int argc,
                            const char (*args)[64]) {
    char line[160];
    if (argc == 0 || k_streq(args[0], "list")) {
        vint_emit(vs, "deauth containment queue (org APs only — AP applies");
        vint_emit(vs, "containment on the target's next association)");
        k_snprintf(line, sizeof(line), "%-18s %-6s %s",
                   "MAC", "STATE", "REASON");
        vint_emit(vs, line);
        for (int i = 0; i < vs->deauth_count; i++) {
            k_snprintf(line, sizeof(line), "%-18s %-6s %s",
                       vs->deauth[i].mac,
                       vs->deauth[i].active ? "on" : "off",
                       vs->deauth[i].reason);
            vint_emit(vs, line);
        }
        if (vs->deauth_count == 0)
            vint_emit(vs, "queue empty");
        vint_audit("deauth list");
        return;
    }
    if (k_streq(args[0], "add") && argc >= 2) {
        if (vs->deauth_count >= VINT_MAX_DEAUTH) {
            vint_emit(vs, "deauth: queue full");
            return;
        }
        vint_deauth_t *dt = &vs->deauth[vs->deauth_count++];
        k_strcpy(dt->mac, args[1], sizeof(dt->mac));
        k_strcpy(dt->reason, argc >= 3 ? args[2] : "rogue device",
                 sizeof(dt->reason));
        dt->active = 1;
        k_snprintf(line, sizeof(line),
                   "deauth add %s (%s) — ORG AP CONTAINMENT ONLY",
                   dt->mac, dt->reason);
        vint_audit(line);
        vint_emitf(vs, "containment queued: %s (%s)", dt->mac, dt->reason);
        return;
    }
    if (k_streq(args[0], "del") && argc >= 2) {
        for (int i = 0; i < vs->deauth_count; i++) {
            if (vint_find_slot(vs->deauth[i].mac, args[1])) {
                for (int j = i; j < vs->deauth_count - 1; j++)
                    vs->deauth[j] = vs->deauth[j + 1];
                vs->deauth_count--;
                k_snprintf(line, sizeof(line), "deauth del %s", args[1]);
                vint_audit(line);
                vint_emitf(vs, "containment removed: %s", args[1]);
                return;
            }
        }
        vint_emitf(vs, "deauth: %s not in queue", args[1]);
        return;
    }
    vint_emit(vs, "usage: deauth [list | add <mac> [reason] | del <mac>]");
}

/* ── traffic ─────────────────────────────────────────────────────── */

static void vint_cmd_traffic(VintState *vs, int argc,
                             const char (*args)[64]) {
    char line[128];
    if (argc == 0 || k_streq(args[0], "list")) {
        vint_emit(vs, "traffic shaping rules (management plane)");
        k_snprintf(line, sizeof(line), "%-16s %-10s %s",
                   "IP", "LIMIT", "PRIO");
        vint_emit(vs, line);
        for (int i = 0; i < vs->traffic_count; i++) {
            k_snprintf(line, sizeof(line), "%-16s %-10s %d/7",
                       vs->traffic[i].ip,
                       vs->traffic[i].kbps ? "shaped" : "unlimited",
                       vs->traffic[i].prio);
            vint_emit(vs, line);
        }
        if (vs->traffic_count == 0) vint_emit(vs, "no rules");
        vint_audit("traffic list");
        return;
    }
    if (k_streq(args[0], "add") && argc >= 3) {
        int kbps = k_atoi(args[2]);
        int prio = (argc >= 4) ? k_atoi(args[3]) : 3;
        if (prio < 0 || prio > 7) prio = 3;
        if (vs->traffic_count >= VINT_MAX_TRAFFIC) {
            vint_emit(vs, "traffic: rule table full");
            return;
        }
        vint_traffic_t *tr = &vs->traffic[vs->traffic_count++];
        k_strcpy(tr->ip, args[1], sizeof(tr->ip));
        tr->kbps = kbps;
        tr->prio = prio;
        k_snprintf(line, sizeof(line), "traffic add %s %dkbps prio %d",
                   tr->ip, kbps, prio);
        vint_audit(line);
        vint_emitf(vs, "rule: %s shaped to %dkbps, prio %d/7",
                   tr->ip, kbps, prio);
        return;
    }
    if (k_streq(args[0], "del") && argc >= 2) {
        for (int i = 0; i < vs->traffic_count; i++) {
            if (vint_find_slot(vs->traffic[i].ip, args[1])) {
                for (int j = i; j < vs->traffic_count - 1; j++)
                    vs->traffic[j] = vs->traffic[j + 1];
                vs->traffic_count--;
                k_snprintf(line, sizeof(line), "traffic del %s", args[1]);
                vint_audit(line);
                vint_emitf(vs, "rule removed: %s", args[1]);
                return;
            }
        }
        vint_emitf(vs, "traffic: no rule for %s", args[1]);
        return;
    }
    vint_emit(vs, "usage: traffic [list | add <ip> <kbps> [prio] | del <ip>]");
}

/* ── https (org-deployed CA inspection) ──────────────────────────── */

static void vint_cmd_https(VintState *vs, int argc,
                           const char (*args)[64]) {
    char line[VINT_CONTENT_LEN + 64];
    if (argc == 0 || k_streq(args[0], "list")) {
        vint_emit(vs, "HTTPS inspection sessions");
        k_snprintf(line, sizeof(line), "%-28s %-4s %-9s %s",
                   "HOST", "TLS", "INSPECTED", "BYTES");
        vint_emit(vs, line);
        for (int i = 0; i < vs->https_count; i++) {
            k_snprintf(line, sizeof(line), "%-28s %-4s %-9s %d",
                       vs->https[i].host,
                       vs->https[i].tls ? "1.3" : "-",
                       vs->https[i].inspected ? "yes" : "no",
                       (int)k_strlen(vs->https[i].content));
            vint_emit(vs, line);
        }
        if (vs->https_count == 0) vint_emit(vs, "no sessions");
        vint_emit(vs, "usage: https ca on|off | read <url> | write <id> <text>");
        vint_audit("https list");
        return;
    }
    if (k_streq(args[0], "ca") && argc >= 2) {
        vs->ca_mode = k_streq(args[1], "on") ? 1 : 0;
        vint_audit(vs->ca_mode ? "https ca on (org CA deployed)" :
                                  "https ca off");
        vint_emitf(vs, "org CA inspection: %s",
                   vs->ca_mode ? "on" : "off");
        return;
    }
    if (k_streq(args[0], "read") && argc >= 2) {
        if (!vs->ca_mode) {
            vint_emit(vs, "https: inspection is off (org CA gate).");
            vint_emit(vs, "enable with: https ca on");
            return;
        }
        if (vs->https_count >= VINT_MAX_HTTPS) {
            vint_emit(vs, "https: session table full");
            return;
        }
        /* real capture: the kernel TLS 1.3 stack fetches the session */
        http_response_t r = http_get(args[1]);
        if (r.status <= 0) {
            vint_emitf(vs, "https: fetch failed for %s", args[1]);
            return;
        }
        vint_https_t *hs = &vs->https[vs->https_count++];
        k_strcpy(hs->host, args[1], sizeof(hs->host));
        hs->tls = r.tls;
        hs->inspected = 1;
        k_strcpy(hs->content, r.body ? r.body : "", sizeof(hs->content));
        http_free(&r);
        k_snprintf(line, sizeof(line), "https read %s (status %d)",
                   hs->host, r.status);
        vint_audit(line);
        vint_emitf(vs, "captured+decrypted: %s", hs->host);
        vint_emit(vs, hs->content);
        return;
    }
    if (k_streq(args[0], "write") && argc >= 3) {
        int id = k_atoi(args[1]);
        if (id < 0 || id >= vs->https_count) {
            vint_emit(vs, "https: no such session id");
            return;
        }
        if (!vs->https[id].inspected) {
            vint_emit(vs, "https: session not inspected yet (https read)");
            return;
        }
        k_strcpy(vs->https[id].content, args[2],
                 sizeof(vs->https[id].content));
        char what[128];
        k_snprintf(what, sizeof(what), "https write session %d (org-managed)",
                   id);
        vint_audit(what);
        vint_emit(vs, "session contents rewritten (org-managed session)");
        return;
    }
    vint_emit(vs, "usage: https [list | ca on|off | read <url> | write <id> <text>]");
}

/* ── route ───────────────────────────────────────────────────────── */

static void vint_cmd_route(VintState *vs, int argc,
                           const char (*args)[64]) {
    char line[128];
    if (argc == 0 || k_streq(args[0], "list")) {
        uint8_t ip[4];
        net_get_ip(ip);
        k_snprintf(line, sizeof(line),
                   "nic %s, host ip %u.%u.%u.%u",
                   net_nic_name(), ip[0], ip[1], ip[2], ip[3]);
        vint_emit(vs, line);
        k_snprintf(line, sizeof(line), "%-16s %-16s %s",
                   "DEST", "GATEWAY", "METRIC");
        vint_emit(vs, line);
        for (int i = 0; i < vs->route_count; i++) {
            k_snprintf(line, sizeof(line), "%-16s %-16s %d",
                       vs->routes[i].dest, vs->routes[i].gw,
                       vs->routes[i].metric);
            vint_emit(vs, line);
        }
        if (vs->route_count == 0) vint_emit(vs, "no custom routes");
        vint_audit("route list");
        return;
    }
    if (k_streq(args[0], "add") && argc >= 3) {
        if (vs->route_count >= VINT_MAX_ROUTES) {
            vint_emit(vs, "route: table full");
            return;
        }
        vint_route_t *rt = &vs->routes[vs->route_count++];
        k_strcpy(rt->dest, args[1], sizeof(rt->dest));
        k_strcpy(rt->gw, args[2], sizeof(rt->gw));
        rt->metric = (argc >= 4) ? k_atoi(args[3]) : 1;
        k_snprintf(line, sizeof(line), "route add %s via %s",
                   rt->dest, rt->gw);
        vint_audit(line);
        vint_emitf(vs, "route added: %s via %s", rt->dest, rt->gw, "");
        return;
    }
    if (k_streq(args[0], "del") && argc >= 2) {
        for (int i = 0; i < vs->route_count; i++) {
            if (vint_find_slot(vs->routes[i].dest, args[1])) {
                for (int j = i; j < vs->route_count - 1; j++)
                    vs->routes[j] = vs->routes[j + 1];
                vs->route_count--;
                k_snprintf(line, sizeof(line), "route del %s", args[1]);
                vint_audit(line);
                vint_emitf(vs, "route removed: %s", args[1]);
                return;
            }
        }
        vint_emitf(vs, "route: no route for %s", args[1]);
        return;
    }
    vint_emit(vs, "usage: route [list | add <dest> <gw> [metric] | del <dest>]");
}

/* ── status / help ───────────────────────────────────────────────── */

static void vint_cmd_status(VintState *vs) {
    char line[128];
    vint_emit(vs, VINT_VERSION);
    uint8_t ip[4], mac[6];
    net_get_ip(ip);
    net_get_mac(mac);
    k_snprintf(line, sizeof(line), "nic: %s", net_nic_name());
    vint_emit(vs, line);
    k_snprintf(line, sizeof(line), "ip: %u.%u.%u.%u  mac: %02x:%02x:%02x:%02x:%02x:%02x",
               ip[0], ip[1], ip[2], ip[3],
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    vint_emit(vs, line);
    k_snprintf(line, sizeof(line), "wifi: %s", wifi_status_str());
    vint_emit(vs, line);
    k_snprintf(line, sizeof(line),
               "devices %d | containment %d | rules %d | routes %d | sessions %d | ca %s",
               vs->device_count, vs->deauth_count, vs->traffic_count,
               vs->route_count, vs->https_count,
               vs->ca_mode ? "on" : "off");
    vint_emit(vs, line);
    vint_audit("status");
}

static void vint_cmd_help(VintState *vs) {
    vint_emit(vs, "vintilities commands (organization router management):");
    vint_emit(vs, "  help | warning        — this list / org-use warning");
    vint_emit(vs, "  status                — router/AP + table summary");
    vint_emit(vs, "  devices [add <mac> <ip> <label>]  — device inventory");
    vint_emit(vs, "  traffic [list|add <ip> <kbps> [prio]|del <ip>] — shaping");
    vint_emit(vs, "  deauth [list|add <mac> [reason]|del <mac>] — containment");
    vint_emit(vs, "  https [list|ca on|off|read <url>|write <id> <text>]");
    vint_emit(vs, "  route [list|add <dest> <gw>|del <dest>] — routing");
    vint_emit(vs, "  clear                 — clear the screen");
    vint_emit(vs, "  exit                  — back to terminalL");
}

/* ── line entry ─────────────────────────────────────────────────── */

void vint_init(VintState *vs, vint_output_fn output, void *output_context) {
    k_memset(vs, 0, sizeof(*vs));
    vs->output = output;
    vs->output_context = output_context;
    vint_show_warning(vs);
    vint_emit(vs, VINT_VERSION);
    vint_emit(vs, "type 'help' for the router management commands");
    vint_audit("shell opened");
}

int vint_run_line(VintState *vs, TerminalLState *tl, const char *line) {
    (void)tl;
    /* tokenize into up to 8 words (same lenient parser style as tobs) */
    char args[8][64];
    int argc = 0;
    const char *p = line;
    while (*p && argc < 8) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        int n = 0;
        while (*p && *p != ' ' && *p != '\t' && n < 63)
            args[argc][n++] = *p++;
        args[argc][n] = 0;
        if (n) argc++;
    }
    if (argc == 0) return 0;
    const char *cmd = args[0];

    if (k_streq(cmd, "exit") || k_streq(cmd, "quit")) {
        vint_audit("shell closed");
        return VINT_EXIT;
    }
    if (k_streq(cmd, "help")) { vint_cmd_help(vs); return 0; }
    if (k_streq(cmd, "warning")) { vint_show_warning(vs); return 0; }
    if (k_streq(cmd, "status")) { vint_cmd_status(vs); return 0; }
    if (k_streq(cmd, "clear")) {
        vint_emit(vs, "\x01CLEAR");
        return 0;
    }
    if (k_streq(cmd, "devices")) {
        if (argc >= 5 && k_streq(args[1], "add")) {
            vint_cmd_devices_add(vs, args[2], args[3], args[4]);
            return 0;
        }
        vint_cmd_devices(vs);
        return 0;
    }
    if (k_streq(cmd, "deauth"))  { vint_cmd_deauth(vs, argc - 1, (const char (*)[64])&args[1]); return 0; }
    if (k_streq(cmd, "traffic")) { vint_cmd_traffic(vs, argc - 1, (const char (*)[64])&args[1]); return 0; }
    if (k_streq(cmd, "https"))   { vint_cmd_https(vs, argc - 1, (const char (*)[64])&args[1]); return 0; }
    if (k_streq(cmd, "route"))   { vint_cmd_route(vs, argc - 1, (const char (*)[64])&args[1]); return 0; }

    vint_emitf(vs, "vintilities: %s: no such command (try 'help')", cmd);
    return 1;
}
