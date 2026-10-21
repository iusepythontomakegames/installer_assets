#pragma once

#include <stdint.h>
#include "terminalL.h"

/*
 * vintilities — the organizational router-management shell.
 *
 * Registered by /usr/bin/vintilities.se (SYSREQ id:
 * vintilities-terminal-command). Scope: organizations managing their
 * OWN WiFi — traffic shaping, device inventory, rogue-device deauth
 * containment, and HTTPS inspection through an org-deployed CA. It is
 * NOT for malicious use; every command appends to the SOD audit log.
 *
 * Modeled on the bobs/tobs host pattern: terminalL's `vintilities`
 * command sets vint_request, the terminal window flips shell_mode 3
 * and feeds lines to vint_run_line().
 */

#define VINT_EXIT          2      /* sentinel — must not collide with 0/1 */
#define VINT_VERSION       "vintilities 1.0 (organizational router shell)"

#define VINT_MAX_DEVICES   16
#define VINT_MAX_DEAUTH    16
#define VINT_MAX_TRAFFIC   16
#define VINT_MAX_ROUTES    8
#define VINT_MAX_HTTPS     8
#define VINT_REASON_LEN    64
#define VINT_HOST_LEN      96
#define VINT_CONTENT_LEN   512

typedef struct {
    char mac[18];                 /* "aa:bb:cc:dd:ee:ff"                */
    char ip[16];
    char label[24];               /* hostname / description            */
    int  rogue;                   /* 1: flagged unauthorized            */
} vint_device_t;

typedef struct {
    char mac[18];                 /* containment target (org APs only)  */
    char reason[VINT_REASON_LEN];
    int  active;
} vint_deauth_t;

typedef struct {
    char ip[16];                  /* target host                        */
    int  kbps;                    /* 0 = unlimited                      */
    int  prio;                   /* 0..7 (802.11 WMM AC mapping)       */
} vint_traffic_t;

typedef struct {
    char dest[16];
    char gw[16];
    int  metric;
} vint_route_t;

typedef struct {
    char host[VINT_HOST_LEN];     /* inspected origin                   */
    int  tls;                    /* 1: captured via kernel TLS 1.3     */
    int  inspected;              /* 1: decrypted via org CA            */
    char content[VINT_CONTENT_LEN]; /* read/write-able session payload */
} vint_https_t;

typedef void (*vint_output_fn)(void *context, const char *line);

typedef struct {
    vint_device_t  devices[VINT_MAX_DEVICES];
    int            device_count;
    vint_deauth_t  deauth[VINT_MAX_DEAUTH];
    int            deauth_count;
    vint_traffic_t traffic[VINT_MAX_TRAFFIC];
    int            traffic_count;
    vint_route_t   routes[VINT_MAX_ROUTES];
    int            route_count;
    vint_https_t   https[VINT_MAX_HTTPS];
    int            https_count;
    int            ca_mode;        /* org-deployed CA inspection gate    */
    int            warning_shown;
    vint_output_fn output;
    void          *output_context;
} VintState;

void vint_init(VintState *vs, vint_output_fn output, void *output_context);

/* Feed one interactive line. Returns VINT_EXIT when the user asked to
 * leave (exit/quit). Other commands return 0 (ok) or 1 (error). */
int  vint_run_line(VintState *vs, TerminalLState *tl, const char *line);
