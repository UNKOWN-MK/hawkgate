#include "hg_user.h"
#include <getopt.h>

/*******************************************************************************************
                                START & STOP ACTION
*******************************************************************************************/
static struct option iface_opts[] = {
    {"iface", required_argument, 0, 'i'},
    {0, 0, 0, 0}};

int parse_start(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:", iface_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        default:
            printf("Unknown option\n");
            print_start_help(prog);
            return FAILED;
        }
    }

    if (!iface[0])
    {
        print_start_help(prog);
        return FAILED;
    }

    return start_action(iface);
}

int parse_stop(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:", iface_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        default:
            print_stop_help(prog);
            return FAILED;
        }
    }

    if (!iface[0])
    {
        print_stop_help(prog);
        return FAILED;
    }

    return stop_action(iface);
}

/*******************************************************************************************
                                ADD ACTION
*******************************************************************************************/
static struct option add_opts[] = {
    {"iface", required_argument, 0, 'i'},
    {"client", required_argument, 0, 'c'},
    {"expire", required_argument, 0, 'e'},
    {"idle", required_argument, 0, 'w'},
    {"DownloadRate", required_argument, 0, 'D'},
    {"UploadRate", required_argument, 0, 'U'},
    {0, 0, 0, 0}};

int parse_add(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    char ip[16] = {0};
    time_t expire = 0;
    time_t idle = 0;
    __u64 D_limit = 0;
    __u64 U_limit = 0;
    __u32 rate_id = RATE_ID_NO_LIMIT;

    int c;
    while ((c = getopt_long(argc, argv, "i:c:e:w:D:U:", add_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        case 'c':
            strncpy(ip, optarg, sizeof(ip) - 1);
            break;
        case 'e':
            expire = atoll(optarg);
            break;
        case 'w':
            idle = atoll(optarg);
            break;
        case 'D':
            D_limit = atoll(optarg);
            break;
        case 'U':
            U_limit = atoll(optarg);
            break;
        default:
            print_add_help(prog);
            return FAILED;
        }
    }

    if (!iface[0] || !ip[0])
    {
        print_add_help(prog);
        return FAILED;
    }

    if (D_limit && U_limit)
    {
        char *ip_last = strdup(ip);
        char *last_dot = strrchr(ip_last, '.');
        rate_id = atoi(last_dot != NULL ? last_dot + 1 : "0");
        printf("hgctl: rate_limit_id = %u\n", rate_id);
        free(ip_last);
    }
    else
    {
        rate_id = RATE_ID_NO_LIMIT;
    }

    return add_action(iface, ip, expire, idle, D_limit, U_limit, rate_id);
}

/*******************************************************************************************
                                DELETE ACTION
*******************************************************************************************/
static struct option del_opts[] = {
    {"iface", required_argument, 0, 'i'},
    {"client", required_argument, 0, 'c'},
    {0, 0, 0, 0}};

int parse_del(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    char ip[16] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:c:", del_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        case 'c':
            strncpy(ip, optarg, sizeof(ip) - 1);
            break;
        default:
            print_del_help(prog);
            return FAILED;
        }
    }

    if (!iface[0] || !ip[0])
    {
        print_del_help(prog);
        return FAILED;
    }

    return del_action(iface, ip);
}

/*******************************************************************************************
                                SHOW & DETAILS ACTION
*******************************************************************************************/
int parse_show(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:", iface_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        default:
            print_show_help(prog);
            return FAILED;
        }
    }

    if (!iface[0])
    {
        print_show_help(prog);
        return FAILED;
    }

    show_action(iface);
    return SUCCESS;
}

int parse_details(int argc, char **argv, const char *prog)
{
    char iface[16] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:", iface_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        default:
            print_details_help(prog);
            return FAILED;
        }
    }

    if (!iface[0])
    {
        print_details_help(prog);
        return FAILED;
    }

    details_action(iface);
    return SUCCESS;
}

/*******************************************************************************************
                                PROTOCOL ALLOW ACTION
*******************************************************************************************/
static struct option proto_opts[] = {
    {"action", required_argument, 0, 'a'},
    {"iface", required_argument, 0, 'i'},
    {"l2", required_argument, 0, 1},
    {"l3", required_argument, 0, 2},
    {"l4", required_argument, 0, 3},
    {0, 0, 0, 0}};

static int parse_l2(char *arg, struct proto_rule *r)
{
    r->level = PROTO_L2;
    r->proto = (__u16)strtoul(arg, NULL, 0);
    r->sport = 0;
    r->dport = 0;
    return SUCCESS;
}

static int parse_l3(char *arg, struct proto_rule *r)
{
    r->level = PROTO_L3;
    r->proto = (__u16)strtoul(arg, NULL, 0);
    r->sport = 0;
    r->dport = 0;
    return SUCCESS;
}

static int parse_l4(char *arg, struct proto_rule *r)
{
    char *p, *s, *d;

    p = strtok(arg, ":");
    s = strtok(NULL, ":");
    d = strtok(NULL, ":");

    if (!p || !s || !d)
        return FAILED;

    r->level = PROTO_L4;
    r->proto = (__u16)strtoul(p, NULL, 0);
    r->sport = (strcmp(s, "any") == 0) ? 0 : atoi(s);
    r->dport = (strcmp(d, "any") == 0) ? 0 : atoi(d);

    return SUCCESS;
}

int parse_proto(int argc, char **argv, const char *prog)
{
    struct proto_rule rule = {0};
    char iface[16] = {0};
    char action_proto[4] = {0};
    int c;

    while ((c = getopt_long(argc, argv, "i:a:", proto_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(iface, optarg, sizeof(iface) - 1);
            break;
        case 'a':
            strncpy(action_proto, optarg, sizeof(action_proto) - 1);
            break;
        case 1:
            parse_l2(optarg, &rule);
            break;
        case 2:
            parse_l3(optarg, &rule);
            break;
        case 3:
            parse_l4(optarg, &rule);
            break;
        default:
            print_proto_help(prog);
            return FAILED;
        }
    }

    if (!iface[0] || !action_proto[0] || rule.level == 0)
    {
        print_proto_help(prog);
        return FAILED;
    }

    if (strcmp(action_proto, "add") == 0)
        return protocol_allow_add_action(&rule);
    else if (strcmp(action_proto, "del") == 0)
        return protocol_allow_del_action(&rule);
    else
    {
        printf("hgctl: unknown proto action '%s'\n", action_proto);
        print_proto_help(prog);
        return FAILED;
    }
}

/*******************************************************************************************
                                HELP FUNCTIONS
*******************************************************************************************/
void print_start_help(const char *prog)
{
    printf(
        "Command: start\n"
        "  %s start -i <iface>\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>   Network interface (e.g. br0)\n"
        "\n"
        "Example:\n"
        "  %s start -i br0\n"
        "\n",
        prog, prog);
}

void print_stop_help(const char *prog)
{
    printf(
        "Command: stop\n"
        "  %s stop -i <iface>\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>   Network interface\n"
        "\n"
        "Example:\n"
        "  %s stop -i br0\n"
        "\n",
        prog, prog);
}

void print_add_help(const char *prog)
{
    printf(
        "Command: add\n"
        "  %s add -i <iface> -c <ip> [-e <sec>] [-w <sec>] [-D <kbps>] [-U <kbps>]\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>          Network interface\n"
        "  -c, --client <ip>            Client IPv4 address\n"
        "  -e, --expire <sec>           Session expiry in seconds (0 = never)\n"
        "  -w, --idle <sec>             Idle timeout in seconds\n"
        "  -D, --DownloadRate <kbps>    Download rate limit in kbit/s\n"
        "  -U, --UploadRate <kbps>      Upload rate limit in kbit/s\n"
        "\n"
        "Example:\n"
        "  %s add -i br0 -c 192.168.100.50 -e 3600 -w 600 -D 10240 -U 5120\n"
        "\n",
        prog, prog);
}

void print_del_help(const char *prog)
{
    printf(
        "Command: del\n"
        "  %s del -i <iface> -c <ip>\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>   Network interface\n"
        "  -c, --client <ip>     Client IPv4 address\n"
        "\n"
        "Example:\n"
        "  %s del -i br0 -c 192.168.100.50\n"
        "\n",
        prog, prog);
}

void print_show_help(const char *prog)
{
    printf(
        "Command: show\n"
        "  %s show -i <iface>\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>   Network interface\n"
        "\n"
        "Example:\n"
        "  %s show -i br0\n"
        "\n",
        prog, prog);
}

void print_details_help(const char *prog)
{
    printf(
        "Command: details\n"
        "  %s details -i <iface>\n"
        "\n"
        "Options:\n"
        "  -i, --iface <iface>   Network interface\n"
        "\n"
        "Example:\n"
        "  %s details -i br0\n"
        "\n",
        prog, prog);
}

void print_proto_help(const char *prog)
{
    printf(
        "Command: proto\n"
        "  %s proto -a <add|del> -i <iface> [--l2 <ethertype> | --l3 <proto> | --l4 <p:s:d>]\n"
        "\n"
        "Options:\n"
        "  -a, --action <add|del>   Add or remove a pre-auth allow rule\n"
        "  -i, --iface <iface>      Network interface\n"
        "      --l2 <ethertype>     Allow L2 EtherType       (e.g. 0x0806 = ARP)\n"
        "      --l3 <proto>         Allow L3 IP proto number (e.g. 1 = ICMP)\n"
        "      --l4 <p:s:d>         Allow L4 proto + ports\n"
        "                           p = IP protocol (6=TCP, 17=UDP)\n"
        "                           s = source port or 'any'\n"
        "                           d = destination port or 'any'\n"
        "\n"
        "Examples:\n"
        "  %s proto -a add -i br0 --l2 0x0806\n"
        "  %s proto -a add -i br0 --l3 1\n"
        "  %s proto -a add -i br0 --l4 17:any:53\n"
        "  %s proto -a del -i br0 --l4 17:any:53\n"
        "\n",
        prog, prog, prog, prog, prog);
}

void print_help(const char *prog)
{
    printf(
        "\n"
        "HawkGate control utility\n"
        "\n"
        "Usage:\n"
        "  %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  start     Load eBPF and attach TC hooks to interface\n"
        "  stop      Detach TC hooks and clean up\n"
        "  add       Authenticate a client\n"
        "  del       Deauthenticate a client\n"
        "  show      Show per-client traffic counters\n"
        "  details   Show detailed client info (state, rate, age)\n"
        "  proto     Manage pre-auth protocol allow rules\n"
        "\n",
        prog);

    print_start_help(prog);
    print_stop_help(prog);
    print_add_help(prog);
    print_del_help(prog);
    print_show_help(prog);
    print_details_help(prog);
    print_proto_help(prog);

    printf(
        "Notes:\n"
        "  - BPF maps are pinned under /sys/fs/bpf/hg/\n"
        "  - Only one protocol rule can be added per 'proto' command\n"
        "  - All protocol values are numeric (no names accepted)\n"
        "  - Enforcement happens in the kernel datapath via eBPF TC hooks\n"
        "\n");
}
