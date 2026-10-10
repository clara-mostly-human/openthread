/*
 * utun_mcast_probe.c -- why does IPV6_JOIN_GROUP(ff02::1) fail with EINVAL on a
 * brand-new macOS utun interface?
 *
 * Research probe for OpenThread's src/posix/platform/netif.cpp UpdateMulticast()
 * "FIX ME" block. It creates utun interfaces exactly the way netif.cpp does
 * (PF_SYSTEM / SYSPROTO_CONTROL / com.apple.net.utun_control) and then, on a
 * fine time grid, records for each interface:
 *
 *   - SIOCGIFFLAGS            (UP / RUNNING / MULTICAST / POINTOPOINT)
 *   - getifaddrs()            (number of inet6 addresses, link-local present?)
 *   - SIOCGIFINFO_IN6         (EINVAL until the kernel's ND6/IPv6 per-interface
 *                              data exists -> "is IPv6 attached to the ifnet?")
 *   - IPV6_JOIN_GROUP result  for ff01::1, ff02::1, ff02::2, ff03::1, ff05::1
 *                              on a fresh AF_INET6/SOCK_DGRAM socket each time,
 *                              ipv6mr_interface = the utun's index.
 *
 * Phases (see main()):
 *   A  fresh utun, passive 3 s, then SIOCSIFFLAGS "up" like netif.cpp SetLinkState()
 *   B  second fresh utun while A is alive
 *   C  close B, create again   -> does the kernel recycle B's ifnet?
 *   D  close A and C, create   -> does the kernel recycle A's ifnet?
 *   E  fresh utun + SIOCPROTOATTACH_IN6 (attach IPv6 only)
 *   F  fresh utun + SIOCAIFADDR_IN6 (add a ULA, what netif.cpp UpdateUnicast does)
 *   G  fresh utun, taken DOWN immediately, passive, then UP again
 *
 * The program only ever touches the utun interfaces it created itself.
 * It must run as root. It never aborts on a probe error; it logs errno and goes on.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

/* Private ioctls (xnu bsd/netinet6/in6_var.h); IPConfiguration uses them to
 * attach IPv6 to an interface. From a 64-bit process struct in6_aliasreq has the
 * in6_aliasreq_64 layout, so the encoded size matches the kernel's _64 variant. */
#ifndef SIOCPROTOATTACH_IN6
#define SIOCPROTOATTACH_IN6 _IOWR('i', 110, struct in6_aliasreq)
#endif

#define TICK_MS 20

static const char *const kGroups[] = {"ff01::1", "ff02::1", "ff02::2", "ff03::1", "ff05::1"};
#define kNumGroups (sizeof(kGroups) / sizeof(kGroups[0]))

struct utun
{
    int      ctlfd;
    char     name[IFNAMSIZ];
    unsigned idx;
    double   created_ms; /* program-relative */
};

static struct timespec g_t0;
static int             g_ip6fd = -1; /* like netif.cpp's sIpFd */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec - g_t0.tv_sec) * 1000.0 + (ts.tv_nsec - g_t0.tv_nsec) / 1e6;
}

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void logf(const char *fmt, ...)
{
    va_list ap;
    printf("[T+%9.1fms] ", now_ms());
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static const char *errname(int e)
{
    static char buf[32];
    switch (e)
    {
    case 0:
        return "OK";
    case EINVAL:
        return "EINVAL";
    case EADDRINUSE:
        return "EADDRINUSE";
    case EADDRNOTAVAIL:
        return "EADDRNOTAVAIL";
    case ENXIO:
        return "ENXIO";
    case ENOENT:
        return "ENOENT";
    case EPERM:
        return "EPERM";
    case EEXIST:
        return "EEXIST";
    case EBUSY:
        return "EBUSY";
    case EAFNOSUPPORT:
        return "EAFNOSUPPORT";
    case EOPNOTSUPP:
        return "EOPNOTSUPP";
    default:
        snprintf(buf, sizeof(buf), "errno%d", e);
        return buf;
    }
}

/* ---- utun creation: copy of netif.cpp platformConfigureTunDevice() (utun variant) ---- */
static int utun_create(struct utun *u, const char *label)
{
    struct sockaddr_ctl addr;
    struct ctl_info     info;
    socklen_t           len;

    memset(u, 0, sizeof(*u));
    u->ctlfd = -1;

    u->ctlfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (u->ctlfd < 0)
    {
        logf("%s: socket(PF_SYSTEM) failed: %s", label, strerror(errno));
        return -1;
    }

    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(u->ctlfd, CTLIOCGINFO, &info) != 0)
    {
        logf("%s: CTLIOCGINFO failed: %s", label, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sc_id      = info.ctl_id;
    addr.sc_len     = sizeof(addr);
    addr.sc_family  = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit    = 0; /* kernel picks the lowest free unit */

    if (connect(u->ctlfd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        logf("%s: connect(utun_control) failed: %s", label, strerror(errno));
        return -1;
    }
    u->created_ms = now_ms();

    len = sizeof(u->name);
    if (getsockopt(u->ctlfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, u->name, &len) != 0)
    {
        logf("%s: getsockopt(UTUN_OPT_IFNAME) failed: %s", label, strerror(errno));
        return -1;
    }
    u->idx = if_nametoindex(u->name);
    logf("%s: created %s ifindex=%u", label, u->name, u->idx);
    return 0;
}

static void utun_close(struct utun *u, const char *label)
{
    if (u->ctlfd >= 0)
    {
        close(u->ctlfd);
        u->ctlfd = -1;
        logf("%s: closed control socket of %s (ifindex was %u)", label, u->name, u->idx);
    }
}

/* ---- probes ---- */
static int try_join(unsigned ifindex, const char *group)
{
    struct ipv6_mreq mreq;
    int              fd, rc, e;

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return errno;
    memset(&mreq, 0, sizeof(mreq));
    inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = ifindex;
    rc = setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
    e  = (rc == 0) ? 0 : errno;
    close(fd);
    return e;
}

static int get_flags(const char *name, short *flags)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
    if (ioctl(g_ip6fd, SIOCGIFFLAGS, &ifr) != 0)
        return errno;
    *flags = ifr.ifr_flags;
    return 0;
}

static void flags_str(short f, char *out, size_t n)
{
    snprintf(out, n, "%s%s%s%s", (f & IFF_UP) ? "UP" : "down", (f & IFF_RUNNING) ? "|RUNNING" : "",
             (f & IFF_MULTICAST) ? "|MULTICAST" : "|nomcast", (f & IFF_POINTOPOINT) ? "|P2P" : "");
}

/* number of inet6 addresses on the interface; *ll = a link-local one is present */
static int count_in6(const char *name, bool *ll)
{
    struct ifaddrs *ifa0 = NULL, *ifa;
    int             n = 0;
    *ll = false;
    if (getifaddrs(&ifa0) != 0)
        return -1;
    for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6 || strcmp(ifa->ifa_name, name) != 0)
            continue;
        n++;
        if (IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr))
            *ll = true;
    }
    freeifaddrs(ifa0);
    return n;
}

/* nd6_ioctl(SIOCGIFINFO_IN6) returns EINVAL while ND_IFINFO(ifp) is NULL or
 * uninitialized, i.e. while IPv6 has never been attached to this ifnet. */
static int nd6_info(const char *name)
{
    struct in6_ondireq ndi;
    memset(&ndi, 0, sizeof(ndi));
    strlcpy(ndi.ifname, name, sizeof(ndi.ifname));
    if (ioctl(g_ip6fd, SIOCGIFINFO_IN6, &ndi) != 0)
        return errno;
    return 0;
}

struct state
{
    short flags;
    int   flags_err;
    int   n_in6;
    bool  ll;
    int   nd6;
    int   join[kNumGroups];
};

static void sample(const struct utun *u, struct state *s)
{
    size_t i;
    memset(s, 0, sizeof(*s));
    s->flags_err = get_flags(u->name, &s->flags);
    s->n_in6     = count_in6(u->name, &s->ll);
    s->nd6       = nd6_info(u->name);
    for (i = 0; i < kNumGroups; i++)
        s->join[i] = try_join(u->idx, kGroups[i]);
}

static void format_state(const struct state *s, char *out, size_t n)
{
    char   fl[48];
    size_t i, off;
    if (s->flags_err)
        snprintf(fl, sizeof(fl), "SIOCGIFFLAGS:%s", errname(s->flags_err));
    else
        flags_str(s->flags, fl, sizeof(fl));
    off = (size_t)snprintf(out, n, "flags=%s in6addrs=%d linklocal=%s nd6info=%s", fl, s->n_in6, s->ll ? "yes" : "no",
                           errname(s->nd6));
    for (i = 0; i < kNumGroups && off < n; i++)
        off += (size_t)snprintf(out + off, n - off, " %s=%s", kGroups[i], errname(s->join[i]));
}

static void print_sample(const struct utun *u, const char *label, const struct state *s)
{
    char line[512];
    format_state(s, line, sizeof(line));
    logf("%s %s t=+%.1fms %s", label, u->name, now_ms() - u->created_ms, line);
}

/* Passive probe loop: one sample every TICK_MS; print on change and at least every 500 ms. */
static void probe_loop(const struct utun *u, const char *label, int duration_ms)
{
    double       start = now_ms(), last_print = -1e9;
    char         prev[512] = "", cur[512];
    struct state s;
    double       first_ll = -1, first_nd6 = -1, first_ff02_1 = -1, first_ff02_2 = -1;
    int          ticks = 0;

    while (now_ms() - start < duration_ms)
    {
        sample(u, &s);
        ticks++;
        format_state(&s, cur, sizeof(cur));
        if (strcmp(cur, prev) != 0 || now_ms() - last_print >= 500.0)
        {
            print_sample(u, label, &s);
            strlcpy(prev, cur, sizeof(prev));
            last_print = now_ms();
        }
        if (first_ll < 0 && s.ll)
            first_ll = now_ms() - u->created_ms;
        if (first_nd6 < 0 && s.nd6 == 0)
            first_nd6 = now_ms() - u->created_ms;
        if (first_ff02_1 < 0 && s.join[1] == 0)
            first_ff02_1 = now_ms() - u->created_ms;
        if (first_ff02_2 < 0 && s.join[2] == 0)
            first_ff02_2 = now_ms() - u->created_ms;
        sleep_ms(TICK_MS);
    }
    logf("%s %s SUMMARY after %d ticks: first nd6info OK at t=%+.1fms, first link-local at t=%+.1fms, first "
         "ff02::1 join OK at t=%+.1fms, first ff02::2 join OK at t=%+.1fms (-1 = never in this phase)",
         label, u->name, ticks, first_nd6, first_ll, first_ff02_1, first_ff02_2);
}

static void probe_once(const struct utun *u, const char *label)
{
    struct state s;
    sample(u, &s);
    print_sample(u, label, &s);
}

/* netif.cpp SetLinkState(): SIOCGIFFLAGS, flip IFF_UP, SIOCSIFFLAGS */
static void set_link_state(const struct utun *u, const char *label, bool up)
{
    struct ifreq ifr;
    char         fl[48];

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, u->name, sizeof(ifr.ifr_name));
    if (ioctl(g_ip6fd, SIOCGIFFLAGS, &ifr) != 0)
    {
        logf("%s %s: SIOCGIFFLAGS failed: %s", label, u->name, strerror(errno));
        return;
    }
    flags_str(ifr.ifr_flags, fl, sizeof(fl));
    logf("%s %s: flags before SIOCSIFFLAGS(%s): %s", label, u->name, up ? "up" : "down", fl);
    ifr.ifr_flags = up ? (ifr.ifr_flags | IFF_UP) : (ifr.ifr_flags & ~IFF_UP);
    if (ioctl(g_ip6fd, SIOCSIFFLAGS, &ifr) != 0)
        logf("%s %s: SIOCSIFFLAGS failed: %s", label, u->name, strerror(errno));
    else
    {
        short f = 0;
        get_flags(u->name, &f);
        flags_str(f, fl, sizeof(fl));
        logf("%s %s: flags after SIOCSIFFLAGS: %s", label, u->name, fl);
    }
}

static void proto_attach_in6(const struct utun *u, const char *label)
{
    struct in6_aliasreq ifra;
    memset(&ifra, 0, sizeof(ifra));
    strlcpy(ifra.ifra_name, u->name, sizeof(ifra.ifra_name));
    if (ioctl(g_ip6fd, SIOCPROTOATTACH_IN6, &ifra) != 0)
        logf("%s %s: SIOCPROTOATTACH_IN6 -> %s", label, u->name, errname(errno));
    else
        logf("%s %s: SIOCPROTOATTACH_IN6 -> OK", label, u->name);
}

/* netif.cpp UpdateUnicast() on __APPLE__: SIOCAIFADDR_IN6 with infinite lifetimes */
static void add_unicast(const struct utun *u, const char *label, const char *addr, int plen)
{
    struct in6_aliasreq ifr6;
    int                 i;

    memset(&ifr6, 0, sizeof(ifr6));
    strlcpy(ifr6.ifra_name, u->name, sizeof(ifr6.ifra_name));
    ifr6.ifra_addr.sin6_family = AF_INET6;
    ifr6.ifra_addr.sin6_len    = sizeof(ifr6.ifra_addr);
    inet_pton(AF_INET6, addr, &ifr6.ifra_addr.sin6_addr);
    ifr6.ifra_prefixmask.sin6_family = AF_INET6;
    ifr6.ifra_prefixmask.sin6_len    = sizeof(ifr6.ifra_prefixmask);
    for (i = 0; i < plen; i++)
        ifr6.ifra_prefixmask.sin6_addr.s6_addr[i / 8] |= (uint8_t)(0x80 >> (i % 8));
    ifr6.ifra_lifetime.ia6t_vltime    = ND6_INFINITE_LIFETIME;
    ifr6.ifra_lifetime.ia6t_pltime    = ND6_INFINITE_LIFETIME;
    ifr6.ifra_lifetime.ia6t_expire    = ND6_INFINITE_LIFETIME;
    ifr6.ifra_lifetime.ia6t_preferred = ND6_INFINITE_LIFETIME;

    if (ioctl(g_ip6fd, SIOCAIFADDR_IN6, &ifr6) != 0)
        logf("%s %s: SIOCAIFADDR_IN6 %s/%d -> %s", label, u->name, addr, plen, errname(errno));
    else
        logf("%s %s: SIOCAIFADDR_IN6 %s/%d -> OK", label, u->name, addr, plen);
}

static void show_ifconfig(const struct utun *u, const char *label)
{
    char cmd[128];
    logf("%s: ifconfig -L -v %s:", label, u->name);
    fflush(stdout);
    snprintf(cmd, sizeof(cmd), "ifconfig -L -v %s 2>&1 | sed 's/^/    /'", u->name);
    (void)system(cmd);
    fflush(stdout);
}

static void show_sysctl(const char *name)
{
    int    v   = 0;
    size_t len = sizeof(v);
    if (sysctlbyname(name, &v, &len, NULL, 0) == 0)
        logf("sysctl %s = %d", name, v);
    else
        logf("sysctl %s: %s", name, strerror(errno));
}

static void list_utuns(const char *label)
{
    struct if_nameindex *ni = if_nameindex(), *p;
    char                 buf[512] = "";
    size_t               off      = 0;
    if (ni == NULL)
        return;
    for (p = ni; p->if_index != 0 && p->if_name != NULL; p++)
        if (strncmp(p->if_name, "utun", 4) == 0 && off < sizeof(buf))
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, " %s(idx %u)", p->if_name, p->if_index);
    if_freenameindex(ni);
    logf("%s: existing utun interfaces:%s", label, buf[0] ? buf : " (none)");
}

int main(void)
{
    struct utun a, b, c, d, p, e, f, g;

    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    setvbuf(stdout, NULL, _IOLBF, 0);

    logf("utun_mcast_probe start, uid=%d euid=%d", getuid(), geteuid());
    show_sysctl("net.inet6.ip6.auto_linklocal");
    show_sysctl("net.inet6.ip6.in6_embedded_scope");
    show_sysctl("net.inet6.ip6.accept_rtadv");
    show_sysctl("net.inet6.ip6.forwarding");
    list_utuns("phase0");

    g_ip6fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if (g_ip6fd < 0)
    {
        logf("socket(AF_INET6) failed: %s", strerror(errno));
        return 1;
    }

    /* ---------------- Phase A: fresh utun, passive ---------------- */
    logf("==== Phase A: fresh utun, no configuration, passive probing for 3 s");
    if (utun_create(&a, "A") != 0)
        return 1;
    probe_once(&a, "A");
    probe_loop(&a, "A", 3000);
    show_ifconfig(&a, "A");
    logf("---- Phase A2: netif.cpp SetLinkState(up) on %s, then 1 s", a.name);
    set_link_state(&a, "A2", true);
    probe_once(&a, "A2");
    probe_loop(&a, "A2", 1000);

    /* ---------------- Phase B: second fresh utun, A alive ---------------- */
    logf("==== Phase B: second fresh utun while %s is alive, passive 3 s", a.name);
    if (utun_create(&b, "B") == 0)
    {
        probe_once(&b, "B");
        probe_loop(&b, "B", 3000);
        show_ifconfig(&b, "B");
    }

    /* ---------------- Phase C: close B, create again ---------------- */
    logf("==== Phase C: close %s, wait 500 ms, create a utun again (does the kernel recycle the ifnet?)", b.name);
    utun_close(&b, "C");
    sleep_ms(500);
    logf("C: if_nametoindex(%s) after close = %u", b.name, if_nametoindex(b.name));
    list_utuns("C");
    if (utun_create(&c, "C") == 0)
    {
        logf("C: new %s ifindex=%u vs closed B %s ifindex=%u -> %s", c.name, c.idx, b.name, b.idx,
             (c.idx == b.idx && strcmp(c.name, b.name) == 0) ? "SAME name and index" : "different");
        probe_once(&c, "C");
        probe_loop(&c, "C", 2000);
    }

    /* ---------------- Phase D: close A and C, create again ---------------- */
    logf("==== Phase D: close %s and %s, wait 500 ms, create a utun again", a.name, c.name);
    utun_close(&a, "D");
    utun_close(&c, "D");
    sleep_ms(500);
    list_utuns("D");
    if (utun_create(&d, "D") == 0)
    {
        logf("D: new %s ifindex=%u vs closed A %s ifindex=%u -> %s", d.name, d.idx, a.name, a.idx,
             (d.idx == a.idx && strcmp(d.name, a.name) == 0) ? "SAME name and index" : "different");
        probe_once(&d, "D");
        probe_loop(&d, "D", 2000);
    }

    /* ---------------- Phase E: fresh ifnet + SIOCPROTOATTACH_IN6 ---------------- */
    logf("==== Phase E: placeholder utun P (expected to recycle), then a never-used utun E; attach IPv6 with "
         "SIOCPROTOATTACH_IN6 right away");
    if (utun_create(&p, "P") == 0)
        probe_once(&p, "P");
    if (utun_create(&e, "E") == 0)
    {
        probe_once(&e, "E");
        proto_attach_in6(&e, "E");
        probe_once(&e, "E");
        probe_loop(&e, "E", 1000);
        show_ifconfig(&e, "E");
    }

    /* ---------------- Phase F: fresh ifnet + SIOCAIFADDR_IN6 ---------------- */
    logf("==== Phase F: never-used utun F; add a ULA with SIOCAIFADDR_IN6 right away (netif.cpp UpdateUnicast)");
    if (utun_create(&f, "F") == 0)
    {
        probe_once(&f, "F");
        add_unicast(&f, "F", "fd7e:5700:7e57::1", 64);
        probe_once(&f, "F");
        probe_loop(&f, "F", 1000);
        show_ifconfig(&f, "F");
    }

    /* ---------------- Phase G: fresh ifnet taken DOWN at once ---------------- */
    logf("==== Phase G: never-used utun G, SIOCSIFFLAGS down immediately, passive 3 s, then up, 2 s");
    if (utun_create(&g, "G") == 0)
    {
        set_link_state(&g, "G", false);
        probe_once(&g, "G");
        probe_loop(&g, "G", 3000);
        set_link_state(&g, "G2", true);
        probe_once(&g, "G2");
        probe_loop(&g, "G2", 2000);
        show_ifconfig(&g, "G");
    }

    logf("==== cleanup");
    utun_close(&d, "cleanup");
    utun_close(&p, "cleanup");
    utun_close(&e, "cleanup");
    utun_close(&f, "cleanup");
    utun_close(&g, "cleanup");
    sleep_ms(500);
    list_utuns("end");
    close(g_ip6fd);
    logf("utun_mcast_probe done");
    return 0;
}
