#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <locale.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <sched.h>
#include <numa.h>
#include <pthread.h>
#include <getopt.h>
//#include <net/if.h>  /* conflicts with DPDK headers. */
#define IF_NAMESIZE	16
/* Convert an interface name to an index, and vice versa.  */
extern unsigned int if_nametoindex (const char *__ifname);
extern char *if_indextoname (unsigned int __ifindex, char *__ifname);

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define PS_MAX_NODES        4
#define PS_MAX_CPUS         64
#define PS_MAX_DEVICES      16
#define PS_MAX_QUEUES       128

#define RTE_LOGTYPE_MAIN    RTE_LOGTYPE_USER1

#define MAX_LATENCY         10000  /* from 0 usec to 9.999 msec */
#define MAX_FLOWS           16384
#define MAX_PATH            260
#define INET_ADDRSTRLEN     16
#define INET6_ADDRSTRLEN    46
#define ETH_EXTRA_BYTES     24  // preamble, padding bytes
#define IP_TYPE_TCP         6
#define IP_TYPE_UDP         17

/* custom flag definitions to examine pcap packet */
#define IPPROTO_IPv6_FRAG_CUSTOM    44
#define IPPROTO_ICMPv6_CUSTOM       58
#define IPPROTO_OSPF_CUSTOM         89

struct rate_limiter_state {
    uint64_t rate;        /** in Mbits/sec. */
    uint64_t started_at;  /** the beginning timestamp. */
    uint64_t sent;        /** in Mbits, including ethernet overheads. */
};

struct pspgen_context {
    /* About myself */
    unsigned num_cpus;
    int my_node;
    int my_cpu;
    uint64_t tsc_hz;

    int num_attached_ports;
    int num_txq_per_port;
    int attached_ports[PS_MAX_DEVICES];  /** The list of node-local ports. */
    int ring_idx;                        /** The queue ID for RX/TX in this core. */
    struct rte_mempool *tx_mempools[PS_MAX_DEVICES];

    /* Options */
    enum {
        UNSET = 0,
        PKTGEN = 1,
        TRACE_REPLAY = 2,
    } mode;

    uint64_t accum_latency;
    uint64_t cnt_latency;

    bool latency_measure;
    bool latency_record;
    char latency_record_prefix[MAX_PATH];
    int latency_offset;
    uint16_t magic_number;

    int num_packets;
    int batch_size;
    int packet_size;
    int min_packet_size;
    int loop_count;
    unsigned time_limit;
    double offered_throughput;

    int num_flows;
    int ip_version;
    bool randomize_flows; /** example: set false when testing all-matching IPsec tunnels */

    /* States */
    rte_atomic16_t working;
    uint64_t elapsed_sec;
    bool use_rate_limiter;
    struct rate_limiter_state rate_limiters[PS_MAX_DEVICES];

    /* Statistics */
    uint64_t total_tx_packets;
    uint64_t total_tx_batches;
    uint64_t total_tx_bytes;
    uint64_t last_total_tx_packets;
    uint64_t last_total_tx_batches;
    uint64_t last_total_tx_bytes;
    uint64_t total_rx_packets;
    uint64_t total_rx_batches;
    uint64_t total_rx_bytes;
    uint64_t last_total_rx_packets;
    uint64_t last_total_rx_batches;
    uint64_t last_total_rx_bytes;
    uint64_t tx_packets[PS_MAX_DEVICES];
    uint64_t tx_batches[PS_MAX_DEVICES];
    uint64_t tx_bytes[PS_MAX_DEVICES];
    uint64_t rx_packets[PS_MAX_DEVICES];
    uint64_t rx_batches[PS_MAX_DEVICES];
    uint64_t rx_bytes[PS_MAX_DEVICES];

    uint64_t last_usec;
    struct tm begin;  /* beginning time in wall-clock */

    uint64_t latency_buckets[MAX_LATENCY];
    FILE *latency_log;
};
static struct pspgen_context *contexts[PS_MAX_CPUS] = {NULL,};

/* Global options. */
static bool debug = false;

/* Available devices in the system */
static int num_devices = -1;
static struct rte_eth_dev_info devices[PS_MAX_DEVICES];
static struct ether_addr my_ethaddrs[PS_MAX_DEVICES];

/* Used devices */
static int num_devices_registered = 0;
static int devices_registered[PS_MAX_DEVICES];

/* Target neighbors */
static int num_neighbors = 0;
static struct ether_addr neighbor_ethaddrs[PS_MAX_DEVICES];

/* Trace replay-related variable & structs */

static bool repeat_trace = false;
char pcap_filename[MAX_PATH] = {0, };
char *pcap_alloc_file;
size_t pcap_filesize;
long pcap_num_pkts_total;
long pcap_num_pkts_not_sent;        // pcap_replaying: temp
uint32_t pcap_file_linktype;

// from pcap format definition
typedef struct pcap_file_header {
    uint32_t magic;     /* magic number */
    u_short version_major;  /* major version number */
    u_short version_minor;  /* minor version number */
    int32_t  thiszone;  /* GMT to local correction */
    uint32_t sigfigs;   /* accuracy of timestamps */
    uint32_t snaplen;   /* max length of captured packets, in octets */
    uint32_t linktype;  /* data link type */
} pcap_file_header_t;

typedef struct pcap_pkthdr {
    uint32_t ts_sec;    /* time stamp */
    uint32_t ts_usec;   /* timestamp microseconds */
    uint32_t caplen;    /* number of octets of packet saved in file */
    uint32_t len;       /* actual length of packet */
} pcap_pkthdr_t;

typedef struct pcap_pkt_info {
    size_t offset_pkt_content;  /* offset of captured packet in pcap file */
    int caplen;            /* actual captured length of packet */
    int len;               /* real length of packet on the link */
} pcap_pkt_info_t;
pcap_pkt_info_t *pcap_pkt_info_arr;
long    pkt_info_arr_index;
/* pcap_replaying: end */

static int ps_bind_cpu(int cpu) {
    struct bitmask *bmask;

    bmask = numa_bitmask_alloc(RTE_MAX_LCORE);
    assert(bmask != NULL);
    assert(cpu >= 0 && cpu < RTE_MAX_LCORE);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, cpu);
    numa_sched_setaffinity(0, bmask);
    numa_bitmask_free(bmask);

    /* skip NUMA stuff for UMA systems */
    if (numa_available() == -1 || numa_max_node() == 0)
        return 0;

    bmask = numa_bitmask_alloc(numa_num_configured_nodes());
    assert(bmask != NULL);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, numa_node_of_cpu(cpu));
    numa_set_membind(bmask);
    numa_bitmask_free(bmask);
    return 0;
}

static bool ps_in_samenode(int cpu, int ifindex)
{
    if (numa_available() == -1 || numa_max_node() == 0)
        return true;

    assert(ifindex >= 0);
    assert(ifindex < PS_MAX_DEVICES);

    /* CPU 0,2,4,6,... -> Node 0,
     * CPU 1,3,5,7,... -> Node 1. */
    int cpu_node = numa_node_of_cpu(cpu);
    assert(cpu_node != -1);

    int if_node = devices[ifindex].pci_dev->numa_node;
    assert(if_node < numa_num_configured_nodes());

    return cpu_node == if_node;
}

static uint64_t ps_get_usec(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    return now.tv_sec * 1000000L + now.tv_nsec / 1000L;
}

static int ether_aton(const char *buf, size_t len, struct ether_addr *addr)
{
    char piece[3];
    int j = 0, k = 0;
    for (int i = 0; i < len; i ++) {
        if (buf[i] == ':') {
            if (j == 0 && i > 0)
                continue;
            else
                return -EINVAL;
        }
        piece[j++] = buf[i];
        if (j == 2) {
            piece[j] = '\0';
            char *endptr;
            addr->addr_bytes[k] = (int) strtol(piece, &endptr, 16);
            if (errno < 0)
                return errno;
            if (endptr == piece)
                return -EINVAL;
            k++;
            if (k == ETHER_ADDR_LEN) break;
            j = 0;
        }
    }
    if (k < ETHER_ADDR_LEN) return -EINVAL;
    return 0;
}

void preprocess_pcap_file() {
    FILE *file;
    size_t read_size;
    size_t offset = 0;
    pcap_pkthdr_t *captured_pkt_hdr;
    pcap_pkt_info_t *pkt_info;

    pcap_num_pkts_total = 0;
    long index = 0;

    printf("Now preprocessing pcap file..\n");

    file = fopen(pcap_filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open the pcap file \"%s\".\n", pcap_filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    pcap_filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    pcap_alloc_file = (char*)malloc(pcap_filesize);
    read_size = fread(pcap_alloc_file, pcap_filesize, 1, file);

    if (read_size == -1) {
        fprintf(stderr, "Failed to read pcap file \"%s\".\n", pcap_filename);
        exit(1);
    }

    pcap_file_header_t *pcap_file_hdr;
    pcap_file_hdr = (pcap_file_header_t *)pcap_alloc_file;
    printf("Link type of packet trace: %u\n", pcap_file_hdr->linktype);
    pcap_file_linktype = pcap_file_hdr->linktype;

    // 1. look through pcap file & count whole number of packets
    offset += sizeof(pcap_file_header_t);
    while (offset < pcap_filesize) {
        captured_pkt_hdr = (pcap_pkthdr_t*) (pcap_alloc_file + offset);
        //printf("Packet #%d captured length: %d\n", pcap_num_pkts_total+1, captured_pkt_hdr->caplen);
        offset += sizeof(pcap_pkthdr_t);
        offset += captured_pkt_hdr->caplen;
        pcap_num_pkts_total++;
    }

    // 2. alloc packet info array
    pcap_pkt_info_arr = (pcap_pkt_info_t*) malloc(pcap_num_pkts_total * sizeof(pcap_pkt_info_t));

    // 3. set packet info into array
    offset = sizeof(pcap_file_header_t);
    while (offset < pcap_filesize) {
        captured_pkt_hdr = (pcap_pkthdr_t*) (pcap_alloc_file + offset);
        //printf("Packet #%d captured length: %d\n", pcap_num_pkts_total+1, captured_pkt_hdr->caplen);
        offset += sizeof(pcap_pkthdr_t);
        pkt_info = &pcap_pkt_info_arr[index];
        pkt_info->offset_pkt_content = offset;
        pkt_info->caplen = captured_pkt_hdr->caplen;
        pkt_info->len   = captured_pkt_hdr->len;
        offset += captured_pkt_hdr->caplen;
        index++;
    }

    printf("File size: %zu, number of packet: %ld\n", pcap_filesize, pcap_num_pkts_total);
}

static void init_rate_limit(struct rate_limiter_state *r, uint64_t bps)
{
    r->rate = bps;  /* bits/sec */
    r->sent = 0;
    r->started_at = rte_get_tsc_cycles();
}

static int64_t check_rate(struct rate_limiter_state *r)
{
    uint64_t now = rte_get_tsc_cycles();
    uint64_t should_have_sent = (uint64_t)((now - r->started_at) / (double) rte_get_tsc_hz() * r->rate);  /* bits */
    return (int64_t) should_have_sent - r->sent;
}

static void update_rate(struct rate_limiter_state *r, uint64_t sent_bits)
{
    uint64_t now = rte_get_tsc_cycles();
    if (r->started_at < now - rte_get_tsc_hz()) {
        r->started_at = now;
        r->sent = 0;
    }
    r->sent += sent_bits;
}

void stop_all(void)
{
    unsigned c;
    RTE_LCORE_FOREACH(c) {
        if (contexts[c] != NULL) {
            rte_atomic16_set(&contexts[c]->working, 0);
        }
    }
}

void handle_signal(int signal)
{
    stop_all();
}

void update_stats(struct rte_timer *tim, void *arg)
{
    struct pspgen_context *ctx = (struct pspgen_context *) arg;
    uint64_t cur_usec = ps_get_usec();
    int64_t usec_diff = cur_usec - ctx->last_usec;

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        ctx->total_tx_packets += ctx->tx_packets[port_idx];
        ctx->total_tx_batches += ctx->tx_batches[port_idx];
        ctx->total_tx_bytes   += ctx->tx_bytes[port_idx];
        ctx->total_rx_packets += ctx->rx_packets[port_idx];
        ctx->total_rx_batches += ctx->rx_batches[port_idx];
        ctx->total_rx_bytes   += ctx->rx_bytes[port_idx];
    }

    char linebuf[512];
    int p = 0;
    uint64_t tx_pps = (ctx->total_tx_packets - ctx->last_total_tx_packets) / (usec_diff / 1e6f);
    uint64_t tx_bps = ((ctx->total_tx_bytes - ctx->last_total_tx_bytes) * 8) / (usec_diff / 1e6f);
    p = sprintf(linebuf, "CPU %d: %'10ld pps, %6.3f Gbps (%5.1f pkts/batch), %'ld",
                ctx->my_cpu, tx_pps, (tx_bps + (tx_pps * ETH_EXTRA_BYTES) * 8) / 1e9f,
                (float) (ctx->total_tx_packets - ctx->last_total_tx_packets)
                        / (ctx->total_tx_batches - ctx->last_total_tx_batches),
                        ctx->cnt_latency
                        );

    if (ctx->latency_measure && ctx->cnt_latency > 0) {
        p += sprintf(linebuf + p, "  %7.2f us (%'9lu samples)",
                     //((ctx->accum_latency / ctx->cnt_latency) / (ctx->tsc_hz / 1e6f)),
                     ( (float)ctx->accum_latency / (float)ctx->cnt_latency),
                     ctx->cnt_latency);
        ctx->accum_latency = 0;
        ctx->cnt_latency = 0;

        if (ctx->latency_record && ctx->latency_log != NULL) {
            fprintf(ctx->latency_log, "----- %lu sec -----\n", ctx->elapsed_sec);
            for (int j = 0; j < MAX_LATENCY; j++) {
                if (ctx->latency_buckets[j] != 0)
                    fprintf(ctx->latency_log, "%u %lu\n", j, ctx->latency_buckets[j]);
            }
            fflush(ctx->latency_log);
            memset(ctx->latency_buckets, 0, sizeof(uint64_t) * MAX_LATENCY);
        }
    }

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        const char *driver = devices[port_idx].driver_name;

        tx_pps = ctx->tx_packets[port_idx];
        tx_bps = ctx->tx_bytes[port_idx] * 8;
        p += sprintf(linebuf + p, "  %s.%d: %'10ld pps,%6.3f Gbps",
                     driver, port_idx, tx_pps, (tx_bps + (tx_pps * ETH_EXTRA_BYTES) * 8) / 1e9f);
    }
    printf("%s\n", linebuf);

    ctx->elapsed_sec ++;
    if (ctx->time_limit > 0 && ctx->elapsed_sec >= ctx->time_limit)
        stop_all();

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        ctx->tx_packets[port_idx] = 0;
        ctx->tx_batches[port_idx] = 0;
        ctx->tx_bytes[port_idx] = 0;
        ctx->rx_packets[port_idx] = 0;
        ctx->rx_batches[port_idx] = 0;
        ctx->rx_bytes[port_idx] = 0;
    }
    ctx->last_total_tx_packets = ctx->total_tx_packets;
    ctx->last_total_tx_batches = ctx->total_tx_batches;
    ctx->last_total_tx_bytes   = ctx->total_tx_bytes;
    ctx->last_total_rx_packets = ctx->total_rx_packets;
    ctx->last_total_rx_batches = ctx->total_rx_batches;
    ctx->last_total_rx_bytes   = ctx->total_rx_bytes;
    ctx->last_usec = cur_usec;
}

static inline uint32_t myrand(uint64_t *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return (uint32_t)(*seed >> 32);
}

void build_packet(char *buf, int size, bool randomize, uint64_t *seed)
{
    struct ether_hdr *eth;
    struct ipv4_hdr *ip;
    struct udp_hdr *udp;
    uint32_t rand_val;

    /* Build an ethernet header */
    eth = (struct ether_hdr *)buf;
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    /* Note: eth->h_source and eth->h_dest are written at send_packets(). */

    /* Build an IPv4 header. */
    ip = (struct ipv4_hdr *)(buf + sizeof(*eth));

    ip->version_ihl = (4 << 4) | 5;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(size - sizeof(*eth));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 4;
    ip->next_proto_id = IP_TYPE_UDP;
    /* Currently we do not test source-routing. */
    ip->src_addr = rte_cpu_to_be_32(0x0A000001);
    if (randomize) {
        /* Prevent generation of multicast packets, though its probability is very low. */
        ip->dst_addr = rte_cpu_to_be_32(myrand(seed));
        unsigned char *daddr = (unsigned char*)(&ip->dst_addr);
        daddr[0] = 0x0A;
    } else {
        uint64_t s = ++(*seed);
        ip->dst_addr = rte_cpu_to_be_32(0x0A000000 | (s & 0x00FFFFFF));
    }

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    udp = (struct udp_hdr *)((char *)ip + sizeof(*ip));

    if (randomize) {
        rand_val = myrand(seed);
    } else {
        rand_val = 80;
    }
    udp->src_port = rte_cpu_to_be_16(rand_val & 0xFFFF);
    udp->dst_port = rte_cpu_to_be_16((rand_val >> 16) & 0xFFFF);
    udp->dgram_len   = rte_cpu_to_be_16(size - sizeof(*eth) - sizeof(*ip));
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    /* For debugging, we fill the packet content with a magic number 0xf0. */
    char *content = (char *)((char *)udp + sizeof(*udp));
    memset(content, 0xf0, size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
    memset(content, 0xee, 1);  /* To indicate the beginning of packet content area. */
}

void build_packet_v6(char *buf, int size, bool randomize, uint64_t *seed)
{
    struct ether_hdr *eth;
    struct ipv6_hdr *ip;
    struct udp_hdr *udp;
    uint32_t rand_val;

    /* Build an ethernet header. */
    eth = (struct ether_hdr *)buf;
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

    /* Note: eth->h_source and eth->h_dest are written at send_packets(). */

    /* Build an IPv6 header. */
    ip = (struct ipv6_hdr *)(buf + sizeof(*eth));
    
    /* 4 bits: version, 8 bits: traffic class, 20 bits: flow label. */
    ip->vtc_flow = rte_cpu_to_be_32(6 << 28);
    ip->payload_len = rte_cpu_to_be_16(size - sizeof(*eth) - sizeof(*ip)); /* The minimum is 10 bytes. */
    ip->proto = IP_TYPE_UDP;
    ip->hop_limits = 4;
    /* Currently we do not test source-routing. */
    ip->src_addr[0] = rte_cpu_to_be_32(0x0A000001);
    ip->src_addr[1] = rte_cpu_to_be_32(0x0C000000);
    ip->src_addr[2] = rte_cpu_to_be_32(0x0B000000);
    ip->src_addr[3] = rte_cpu_to_be_32(0x0E000000);
    ip->dst_addr[0] = rte_cpu_to_be_32(myrand(seed));
    ip->dst_addr[1] = rte_cpu_to_be_32(myrand(seed));
    ip->dst_addr[2] = rte_cpu_to_be_32(myrand(seed));
    ip->dst_addr[3] = rte_cpu_to_be_32(myrand(seed));

    // TODO: implement randomize flag for IPv6 too.

    /* Prevent generation of multicast packets. */
    unsigned char *daddr_first_byte = (unsigned char*)(&ip->dst_addr[0]);
    daddr_first_byte[0] = 0x0A;

    udp = (struct udp_hdr *)((char *)ip + sizeof(*ip));

    rand_val = myrand(seed);
    udp->src_port = rte_cpu_to_be_16(rand_val & 0xFFFF);
    udp->dst_port = rte_cpu_to_be_16((rand_val >> 16) & 0xFFFF);
    udp->dgram_len   = rte_cpu_to_be_16(size - sizeof(*eth) - sizeof(*ip));
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip, udp);

    /* For debugging, we fill the packet content with a magic number 0xf0. */
    char *content = (char *)((char *)udp + sizeof(*udp));
    memset(content, 0xf0, size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
    memset(content, 0xee, 1);  /* To indicate the beginning of packet content area. */
}

void build_packet_from_trace(char *buf, char* packet, int captured_size, int actual_size) {
    // Copy the whole captured pcap packet.
    // It's okay because currently we only use ethernet address in routing, which is overwritten after packet is built.
    size_t filled_size = 0;

    if (pcap_file_linktype == 1) /* LINKTYPE_ETHERNET */
    {
        memcpy(buf, packet, captured_size);
        filled_size = captured_size;
    }
    else if (pcap_file_linktype == 101) /* LINKTYPE_RAW */
    {
        // Just to check whether raw packet is IPv4 or IPv6.
        // It is okay because the version field of IPv4 & IPv6 is in same position.
        // XXX: This code only handles IPv4 & IPv6 packet as L3 packet.
        struct ipv4_hdr *l3_header = (struct ipv4_hdr *) packet;
        struct ether_hdr *eth = (struct ether_hdr *) buf;
        int ip_version = (l3_header->version_ihl & 0xf0) >> 4;
        if (ip_version == 4) {
            eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
        } else if (ip_version == 6) {
            eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
        }
        memcpy(buf + sizeof(*eth), packet, captured_size);
        filled_size = sizeof(*eth) + captured_size;
    }
    else {
        printf("Linktype %d of pcap file is unhandled currently.\n", pcap_file_linktype);
        exit(1);
    }

    if (filled_size < actual_size) {
        // Fill the rest of packet with a magic number 0xf0.
        memset(buf + filled_size, 0xf0, actual_size - filled_size);
        memset(buf + filled_size, 0xee, 1); // Indicating the beginning of packet content area.
    }
}

int send_packets(void *arg)
{
    struct pspgen_context *ctx = contexts[rte_lcore_id()];
    if (ctx == NULL) return 0;
    assert(ctx->my_cpu == rte_lcore_id());
    ps_bind_cpu(ctx->my_cpu);

    char **packet_src = rte_zmalloc("pktsrc", sizeof(char *) * MAX_FLOWS, RTE_CACHE_LINE_SIZE);
    assert(packet_src != NULL);
    for (int f = 0; f < ctx->num_flows; f++)
        packet_src[f] = rte_malloc("pktsrc", ETHER_MAX_LEN, RTE_CACHE_LINE_SIZE);
    unsigned int next_flow[PS_MAX_DEVICES];
    uint64_t seed = 0;

    struct rte_timer *stat_timer = rte_zmalloc("timer", sizeof(struct rte_timer), RTE_CACHE_LINE_SIZE);
    assert(stat_timer != NULL);
    rte_timer_init(stat_timer);
    rte_timer_reset(stat_timer, rte_get_timer_hz() * 1, PERIODICAL, ctx->my_cpu, update_stats, (void *) ctx);

    if (ctx->num_flows == 0)
        seed = time(NULL) + ctx->my_cpu;

    /* Initialize PCAP replay. */
    pkt_info_arr_index = ctx->my_cpu;
    pcap_num_pkts_not_sent = 0;

    // NOTE: If the num_flows option is used, the flow is generated
    // with maximum sized packets and those sizes are cut randomly when
    // filling the output chunk.
    for (int f = 0; f < ctx->num_flows; f++) {
        if (ctx->ip_version == 4)
            build_packet(packet_src[f], ctx->packet_size, ctx->randomize_flows, &seed);
        else if (ctx->ip_version == 6)
            build_packet_v6(packet_src[f], ctx->packet_size, ctx->randomize_flows, &seed);
    }

    for (int port_idx = 0; port_idx < ctx->num_attached_ports; port_idx++) {
        next_flow[port_idx] = 0;
    }
    if (ctx->latency_measure) {
        if (ctx->ip_version == 4)
            ctx->latency_offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
        else
            ctx->latency_offset = sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + sizeof(struct udp_hdr);
        unsigned min_pkt_size_for_latency = ctx->latency_offset + sizeof(uint16_t) + sizeof(uint64_t);
        if (min_pkt_size_for_latency > ctx->min_packet_size)
            rte_exit(EXIT_FAILURE, "The packet size be must be larger than %u bytes for latency measurement!\n", min_pkt_size_for_latency);
    }

    if (ctx->offered_throughput > 0.0) {
        /* Calculate desired the TX rate for me. */
        /* The net rate of all pspgen instances should be offered_throughput. */
        uint64_t actual_rate = (uint64_t) ((ctx->offered_throughput * 1e9)  /* bps */
                                           / ctx->num_attached_ports / ctx->num_cpus);
        printf("TX rate limit: %'lu bps per port per core\n", actual_rate);
        ctx->use_rate_limiter = false;
        for (int i = 0; i < ctx->num_attached_ports; i++) {
            int port_idx = ctx->attached_ports[i];
            if (ctx->latency_measure) {
                /* HW rate limiter causes high latnecy because the timing
                 * of timestamping and transmission differs significantly.
                 * Latency measurement should use SW rate limiter always
                 * unless we use hardware timestamping. */
                printf("  Setting SW rate limiter for latency measurements...\n");
                ctx->use_rate_limiter = true;
                init_rate_limit(&ctx->rate_limiters[port_idx], actual_rate);
            } else {
                /* Try hardware-supported rate limiting. */
                /* NOTE: ixgbe's hardware rate limiter take account of CRC tail
                 *       of Ethernet frames! */
                /* NOTE: Since we need estimated packet counts to adjust the
                 *       rate limiter, the rate limiting may not be accurate
                 *       when using traces and random sized packets. */
                uint64_t rate_adj =  actual_rate * (ETH_EXTRA_BYTES - ETHER_CRC_LEN) / (ctx->packet_size + ETH_EXTRA_BYTES);
                int ret = rte_eth_set_queue_rate_limit(port_idx, ctx->ring_idx, (uint16_t) ((actual_rate - rate_adj) / 1e6));
                if (ret == -ENOTSUP) {
                    printf("  HW rate limiter is not available, falling back to software rate limiter.\n");
                    ctx->use_rate_limiter = true;
                    init_rate_limit(&ctx->rate_limiters[port_idx], actual_rate);
                } else {
                    printf("  Setting HW rate limiter on %d:%d (result: %s)\n", port_idx, ctx->ring_idx, strerror(ret));
                    assert(ret == 0);
                }
            }
        }
    }

    if (ctx->latency_measure && ctx->latency_record) {
        char latency_log_name[MAX_PATH];
        snprintf(latency_log_name, sizeof(latency_log_name), "latency-%s-cpu%02d-%02d%02d%02d.%02d%02d%02d.log",
                 ctx->latency_record_prefix, ctx->my_cpu, ctx->begin.tm_year, ctx->begin.tm_mon + 1, ctx->begin.tm_mday,
                 ctx->begin.tm_hour, ctx->begin.tm_min, ctx->begin.tm_sec);
        ctx->latency_log = fopen(latency_log_name, "w");
    }

    rte_atomic16_init(&ctx->working);
    rte_atomic16_set(&ctx->working, 1);
    size_t total_sent_cnt = 0;

    while (rte_atomic16_read(&ctx->working) == 1) {

        for (int i = 0; i < ctx->num_attached_ports; i++) {
            int port_idx = ctx->attached_ports[i];
            int64_t need_to_send_bytes = 0;
            struct rte_mbuf *pkts[ctx->batch_size];

            if (ctx->offered_throughput > 0 && ctx->use_rate_limiter) {
                need_to_send_bytes = check_rate(&ctx->rate_limiters[port_idx]);
                if (need_to_send_bytes <= 0)
                    goto skip_tx_packets;
            }

            /* Fill the chunk with packets generated. */
            assert(NULL != ctx->tx_mempools[port_idx]);
            assert(0 == rte_mempool_sc_get_bulk(ctx->tx_mempools[port_idx], (void **) &pkts[0], ctx->batch_size));
            for (int j = 0; j < ctx->batch_size; j++) {
                int cur_pkt_size;
                pkts[j]->refcnt = 1;
                pkts[j]->nb_segs = 1;
                pkts[j]->ol_flags = 0;

                char *buf = rte_pktmbuf_mtod(pkts[j], char *);

                if (ctx->mode == TRACE_REPLAY) {
                    pcap_pkt_info_t *packet = &pcap_pkt_info_arr[pkt_info_arr_index];
                    cur_pkt_size = packet->len;
                    build_packet_from_trace(buf,
                                pcap_alloc_file + packet->offset_pkt_content,
                                packet->caplen, packet->len);

                    if (pkt_info_arr_index < (pcap_num_pkts_total - 1 - ctx->num_cpus)) {
                        pkt_info_arr_index += ctx->num_cpus;
                    }
                } else {
                    if (ctx->min_packet_size < ctx->packet_size)
                        cur_pkt_size = (myrand(&seed) % (ctx->packet_size - ctx->min_packet_size))
                                       + ctx->min_packet_size;
                    else
                        cur_pkt_size = ctx->packet_size;

                    if (ctx->num_flows == 0) {
                        if (ctx->ip_version == 4) {
                            build_packet(buf, cur_pkt_size, ctx->randomize_flows, &seed);
                        } else {
                            build_packet_v6(buf, cur_pkt_size, ctx->randomize_flows, &seed);
                        }
                    } else {
                        rte_memcpy(buf, packet_src[(next_flow[port_idx] + j) % ctx->num_flows], cur_pkt_size);
                    }
                }
                rte_pktmbuf_data_len(pkts[j]) = cur_pkt_size;
                rte_pktmbuf_pkt_len(pkts[j])  = cur_pkt_size;

                /* Write the src/dest ethernet address corresponding to the
                 * outgoing ifindex, like 1-to-1 wired setup. */
                struct ether_hdr *eth = (struct ether_hdr *) buf;
                memcpy(&eth->d_addr, &neighbor_ethaddrs[port_idx], ETHER_ADDR_LEN);
                memcpy(&eth->s_addr, &my_ethaddrs[port_idx], ETHER_ADDR_LEN);
            }

            if (ctx->latency_measure) {
                // Sangwook: Using HPET(clock_gettime()) instead of TSC
                // to measure latency between TX & RX packet on different cores.
                //uint64_t timestamp = rte_get_tsc_cycles();
                struct timespec timestamp;
                clock_gettime(CLOCK_MONOTONIC_RAW, &timestamp);

                for (int j = 0; j < ctx->batch_size; j++) {
                    char *ptr = rte_pktmbuf_mtod(pkts[j], char *) + ctx->latency_offset;
                    *((uint16_t *)ptr) = ctx->magic_number;
                    //*((uint64_t *)(ptr + sizeof(uint16_t))) = timestamp;
                    *((struct timespec *)(ptr + sizeof(struct timespec))) = timestamp;
                }
            }

            unsigned sent_cnt = 0;
            unsigned to_send  = ctx->batch_size; //RTE_MAX(1, RTE_MIN(ctx->batch_size, (int) ((float) need_to_send_bytes / ctx->packet_size)));
            unsigned sent_bytes = 0;
            sent_cnt = rte_eth_tx_burst((uint8_t) port_idx, ctx->ring_idx, pkts, to_send);
            for (int j = 0; j < sent_cnt; j++)
                sent_bytes += rte_pktmbuf_data_len(pkts[j]);
            if (sent_cnt < to_send)
                rte_mempool_sp_put_bulk(ctx->tx_mempools[port_idx], (void **) &pkts[sent_cnt], to_send - sent_cnt);
            ctx->tx_bytes[port_idx] += sent_bytes;
            if (ctx->offered_throughput > 0 && ctx->use_rate_limiter) {
                update_rate(&ctx->rate_limiters[port_idx], (sent_cnt * ETH_EXTRA_BYTES + sent_bytes) * 8);
            }
            /* PCAP replay: check the number of packets not sent */
            pcap_num_pkts_not_sent += ctx->batch_size - sent_cnt;

            /* Update stats. */
            total_sent_cnt += sent_cnt;
            ctx->tx_packets[port_idx] += sent_cnt;
            ctx->tx_batches[port_idx] += 1;

            if ((ctx->mode == TRACE_REPLAY) && (pkt_info_arr_index >= (pcap_num_pkts_total - 1 - ctx->num_cpus))) {
                if (repeat_trace) {
                    pkt_info_arr_index = ctx->my_cpu;
                } else {
                    printf("CPU#%d: End of pcap file\n", ctx->my_cpu);
                    break;
                }
            }

            if (ctx->num_packets <= total_sent_cnt)
                break;

            if (ctx->num_flows)
                next_flow[port_idx] = (next_flow[port_idx] + sent_cnt) % ctx->num_flows;

skip_tx_packets:
            if (ctx->offered_throughput > 0 && ctx->use_rate_limiter) {
                update_rate(&ctx->rate_limiters[port_idx], 0);
            }
            if (ctx->latency_measure) {
                unsigned recv_cnt = rte_eth_rx_burst(port_idx, ctx->ring_idx, &pkts[0], ctx->batch_size);
                // Sangwook: Using HPET(clock_gettime()) instead of TSC
                // to measure latency between TX & RX packet on different cores.
                //uint64_t timestamp = rte_get_tsc_cycles();
                struct timespec timestamp;
                clock_gettime(CLOCK_MONOTONIC_RAW, &timestamp);

                if (recv_cnt > 0) {
                    //printf("Got pkt!\n");
                }
                for (unsigned j = 0; j < recv_cnt; j++) {
                    char *buf = rte_pktmbuf_mtod(pkts[j], char *) + ctx->latency_offset;

                    // Now latency can be checked by using timestamps from different cores.
                    //if (*(uint16_t *)buf == ctx->magic_number) {
                        /*
                        uint64_t old_rdtsc = *(uint64_t *)(buf + sizeof(uint16_t));
                        uint64_t latency = timestamp - old_rdtsc;
                        */
                        struct timespec timestamp_old = *(struct timespec *)(buf + sizeof(struct timespec));
                        uint64_t latency = (timestamp.tv_sec - timestamp_old.tv_sec) * 1e6 + (timestamp.tv_sec - timestamp_old.tv_nsec) / 1000;
                        ctx->cnt_latency ++;
                        ctx->accum_latency += latency;
                        /*
                        unsigned latency_us = (unsigned) (latency / (ctx->tsc_hz / 1e6f));
                        ctx->latency_buckets[RTE_MIN((unsigned) MAX_LATENCY, latency_us)]++;
                        */
                        ctx->latency_buckets[RTE_MIN((unsigned) MAX_LATENCY, latency)]++;
                    //}

                    ctx->rx_bytes[port_idx] += rte_pktmbuf_pkt_len(pkts[j]);
                    rte_pktmbuf_free(pkts[j]);
                }

                ctx->rx_packets[port_idx] += recv_cnt;
                ctx->rx_batches[port_idx] += 1;
            }
        } /* end of for(attached_ports) */

        rte_timer_manage();

    } /* end of while(working) */
    if (ctx->latency_measure && ctx->latency_record && ctx->latency_log != NULL) {
        fclose(ctx->latency_log);
        ctx->latency_log = NULL;
    }

    usleep(10000 * (ctx->my_cpu + 1));
    if (ctx->my_cpu == 0) printf("----------\n");
    printf("CPU %d: total %'lu packets, %'lu bytes transmitted\n",
            ctx->my_cpu, ctx->total_tx_packets, ctx->total_tx_bytes);
    if (ctx->mode == TRACE_REPLAY) {
        printf("CPU %d: total %ld packets not transmitted due to TX drop\n",
               ctx->my_cpu, pcap_num_pkts_not_sent);   // pcap_replaying
    }

    return 0;
}

void print_usage(const char *program)
{
    printf("Usage: %s [EAL options] -- [PSPGEN options]\n\n", program);
    printf("To use in packet-generator (pktgen) mode:\n");
    printf("  %s "
           "-i all|dev1 [-i dev2] ... "
           "[-n <num_packets>] "
           "[-s <chunk_size>] "
           "[-p <packet_size>] "
           "[--min-pkt-size <min_packet_size>] "
           "[-f <num_flows>] "
           "[-r <randomize_flows>] "
           "[-v <ip_version>] "
           "[-l <latency_measure>] "
           "[--latency-record-prefix <prefix>] "
           "[-c <loop_count>] "
           "[-t <seconds>] "
           "[-g <offered_throughput>] "
           "[--debug] "
           "[--loglevel <debug|info|...|critical|emergency>] "
           "[--neighbor-conf <neighbor_config_file>]\n",
           program);
    printf("\nTo replay traces (currently only supports pcap):\n");
    printf("  %s -i all|dev1 [-i dev2] ... --trace <file_name> [--repeat] [--debug]\n\n", program);

    printf("  default <num_packets> is 0. (0 = infinite)\n");
    printf("    (note: <num_packets> is a per-cpu value.)\n");
    printf("  default <batch_size> is 32. packets per batch\n");
    printf("  default <packet_size> is 60. (w/o 4-byte CRC)\n");
    printf("  default <min_packet_size> is same to <packet_size>.\n"
           "    If set, it will generate packets randomly sized\n"
           "    between <min_packet_size> and <packet_size>.\n"
           "    Must follow after <packet_size> option to be effective.\n");
    printf("  default <num_flows> is 0. (0 = infinite)\n");
    printf("  default <randomize_flows> is 1. (0 = off)\n");
    printf("  default <ip_version> is 4. (6 = ipv6)\n");
    printf("  default <latency_measure> is 0. (1 = on)\n");
    printf("  default <prefix> is none (don't record latency histogram into files).\n");
    printf("  default <loop_count> is 1. (only valid for latency mesaurement)\n"); // TODO: re-implement
    printf("  default <seconds> is 0. (0 = infinite)\n");
    printf("  default <offered_throughput> is maximum possible. (Gbps including Ethernet overheads)\n");
    printf("  default <neighbor_config_file> is ./neighbors.conf\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    unsigned loglevel = RTE_LOG_WARNING;
    int ret;
    int mode = UNSET;

    unsigned num_cpus    = 0;
    int num_packets = 0;
    int batch_size  = 32;
    int packet_size = 60;
    int min_packet_size = -1;
    int loop_count  = 1;
    unsigned time_limit = 0;

    int num_flows  = 0;
    int ip_version = 4;
    bool randomize_flows = true;

    bool latency_measure = false;
    bool latency_record  = false;
    char latency_record_prefix[MAX_PATH] = {0,};
    double offered_throughput = -1.0f;

    char neighbor_conf_filename[MAX_PATH] = "neighbors.conf";

    uint64_t begin, end;
    time_t rawtime;
    time(&rawtime);
    struct tm begin_datetime = *localtime(&rawtime);

    setlocale(LC_NUMERIC, "");
    rte_set_log_level(RTE_LOG_WARNING);
    rte_set_application_usage_hook(print_usage);
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters.\n");
    argc -= ret;
    argv += ret;

    /* Initialize system information. */
    num_cpus = rte_lcore_count();
    assert(num_cpus >= 1);
    num_devices = rte_eth_dev_count();
    assert(num_devices != -1);
    if (num_devices == 0)
        rte_exit(EXIT_FAILURE, "There is no detected device.\n");
    for (int i = 0; i < num_devices; i++) {
        rte_eth_dev_info_get((uint8_t) i, &devices[i]);
        rte_eth_macaddr_get((uint8_t) i, &my_ethaddrs[i]);
    }

    /* Argument parsing. */
    struct option long_opts[] = {
        {"repeat", no_argument, NULL, 0},
        {"trace", required_argument, NULL, 0},
        {"debug", no_argument, NULL, 0},
        {"loglevel", required_argument, NULL, 0},
        {"latency-record-prefix", required_argument, NULL, 0},
        {"min-pkt-size", required_argument, NULL, 0},
        {"neighbor-conf", required_argument, NULL, 0},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };
    mode = UNSET;
    while (true) {
        int optidx = 0;
        int c = getopt_long(argc, argv, "i:n:s:p:f:v:c:t:g:rlh", long_opts, &optidx);
        if (c == -1) break;
        switch (c) {
        case 0:
            if (!strcmp("repeat", long_opts[optidx].name)) {
                if (mode == UNSET || mode == TRACE_REPLAY) {
                    repeat_trace = true;
                    mode = TRACE_REPLAY;
                } else {
                    fprintf(stderr, "Trace-replay mode options are exclusive to pktgen mode options.\n");
                    print_usage(argv[0]);
                }
            } else if (!strcmp("trace", long_opts[optidx].name)) {
                if (mode == UNSET || mode == TRACE_REPLAY) {
                    strncpy(pcap_filename, optarg, MAX_PATH);
                    assert((strnlen(pcap_filename, MAX_PATH) > 0));
                    mode = TRACE_REPLAY;
                } else {
                    fprintf(stderr, "Trace-replay mode options are exclusive to pktgen mode options.\n");
                    print_usage(argv[0]);
                }
            } else if (!strcmp("loglevel", long_opts[optidx].name)) {
                assert(optarg != NULL);
                if (!strcmp("debug", optarg))
                    loglevel = RTE_LOG_DEBUG;
                else if (!strcmp("info", optarg))
                    loglevel = RTE_LOG_INFO;
                else if (!strcmp("notice", optarg))
                    loglevel = RTE_LOG_NOTICE;
                else if (!strcmp("warning", optarg))
                    loglevel = RTE_LOG_WARNING;
                else if (!strcmp("error", optarg))
                    loglevel = RTE_LOG_ERR;
                else if (!strcmp("critical", optarg))
                    loglevel = RTE_LOG_CRIT;
                else if (!strcmp("emergency", optarg))
                    loglevel = RTE_LOG_EMERG;
                else
                    rte_exit(EXIT_FAILURE, "Invalid value for loglevel: %s\n", optarg);
            } else if (!strcmp("latency-record-prefix", long_opts[optidx].name)) {
                assert(optarg != NULL);
                latency_record = true;
                strncpy(latency_record_prefix, optarg, MAX_PATH);
            } else if (!strcmp("debug", long_opts[optidx].name)) {
                debug = true;
            } else if (!strcmp("min-pkt-size", long_opts[optidx].name)) {
                mode = PKTGEN;
                min_packet_size = atoi(optarg);
                assert(min_packet_size >= 60 && min_packet_size <= packet_size);
            } else if (!strcmp("neighbor-conf", long_opts[optidx].name)) {
                mode = PKTGEN;
                strncpy(neighbor_conf_filename, optarg, MAX_PATH);
                assert(strnlen(neighbor_conf_filename, MAX_PATH) > 0);
            }
            break;
        case 'h':
            print_usage(argv[1]);
            break;
        case 'i': {
            int ifindex = -1;
            int j;
            if (optarg == NULL)
                rte_exit(EXIT_FAILURE, "-i option requires an argument.\n");

            /* Register all devices. */
            if (!strcmp(optarg, "all")) {
                for (j = 0; j < num_devices; j++)
                    devices_registered[j] = j;
                num_devices_registered = num_devices;
                continue;
            }

            /* Or, register one by one. */
            for (j = 0; j < num_devices; j++) {
                char ifname[64];
                // Example of interface name: igb_uio.2
                snprintf(ifname, 64, "%s.%d", devices[j].driver_name, j);
                if (!strcmp(optarg, ifname))
                    ifindex = j;
            }

            if (ifindex == -1)
                rte_exit(EXIT_FAILURE, "device %s does not exist!\n", optarg);

            for (j = 0; j < num_devices_registered; j++)
                if (devices_registered[j] == ifindex)
                    rte_exit(EXIT_FAILURE, "device %s is registered more than once!\n", optarg);

            devices_registered[num_devices_registered] = ifindex;
            num_devices_registered ++;
            } break;
        case 'n':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            num_packets = atoi(optarg);
            assert(num_packets >= 0);
            if (num_packets < (signed) num_cpus / num_devices)
                fprintf(stderr, "WARNING: Too few packets would not utilize some interfaces.\n");
            break;
        case 's':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            batch_size = atoi(optarg);
            assert(batch_size >= 1 && batch_size <= 1500);
            break;
        case 'p':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            packet_size = atoi(optarg);
            assert(packet_size >= 60 && packet_size <= 1514);
            break;
        case 'f':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            num_flows = atoi(optarg);
            assert(num_flows >= 0 && num_flows <= MAX_FLOWS);
            break;
        case 'r':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            if (optarg == NULL)
                randomize_flows = true;
            else
                randomize_flows = (bool) atoi(optarg);
            break;
        case 'v':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            ip_version = atoi(optarg);
            assert(ip_version == 4 || ip_version == 6);
            break;
        case 'l':
            if (optarg == NULL)
                latency_measure = true;
            else
                latency_measure = (bool) atoi(optarg);
            break;
        case 'c':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            loop_count = atoi(optarg);
            assert(loop_count >= 1);
            break;
        case 't':
            if (!(mode == UNSET || mode == PKTGEN))
                rte_exit(EXIT_FAILURE, "Pktgen mode options are exclusive to trace-replay mode options.\n");
            mode = PKTGEN;
            time_limit = (unsigned) atoi(optarg);
            break;
        case 'g':
            offered_throughput = atof(optarg);
            assert(offered_throughput > 0);
            break;
        case '?':
            rte_exit(EXIT_FAILURE, "Unknown option or missing argument: %c\n", optopt);
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
    if (mode == UNSET)
        print_usage(argv[0]);
    if (min_packet_size == -1)
        min_packet_size = packet_size;
    if (!randomize_flows && num_flows == 0)
        rte_exit(EXIT_FAILURE, "Number of flows must be specified when you use -r option (non-random dest address).\n");
    if (offered_throughput > 0 && min_packet_size != packet_size)
        rte_exit(EXIT_FAILURE, "Throughput regulation for random sized packets is not supported yet.\n");
    if (num_devices_registered == 0)
        rte_exit(EXIT_FAILURE, "No devices registered!\n");
    rte_set_log_level(loglevel);

    /* Read neighbor configuration from file.
     * We currently do not use IP addresses since experimenting a router uses random IP
     * addresses.  (It's for correctness test in the future.) */

    FILE *f = fopen(neighbor_conf_filename, "r");
    if (f == NULL) {
        fprintf(stderr, "Cannot open the neighbor configuration file \"%s\".\n", neighbor_conf_filename);
        exit(1);
    }
    num_neighbors = 0;
    char *eth_straddr = (char *)malloc(sizeof(char) * 32);
    char *ipv4_straddr = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
    char *ipv6_straddr = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
    if (ip_version == 4) {
        while (EOF != fscanf(f, "%s %s", eth_straddr, ipv4_straddr) && num_neighbors < PS_MAX_DEVICES) {
            assert(0 == ether_aton(eth_straddr, ETHER_ADDR_LEN * 3, &neighbor_ethaddrs[num_neighbors]));
            // TODO: implement IP address parsing.
            //neighbor_ipv4addrs[num_neighbors] = NTOHL(inet_addr(ipv4_straddr));
            num_neighbors++;
        }
    } else if (ip_version == 6) {
        while (EOF != fscanf(f, "%s %s", eth_straddr, ipv6_straddr) && num_neighbors < PS_MAX_DEVICES) {
            assert(0 == ether_aton(eth_straddr, ETHER_ADDR_LEN * 3, &neighbor_ethaddrs[num_neighbors]));
            // TODO: implement IP address parsing.
            num_neighbors++;
        }
    }
    free(eth_straddr);
    free(ipv4_straddr);
    free(ipv6_straddr);
    fclose(f);
    /* Currently we only permit the 1-to-1 wired configuration for simplicity.
     * To avoid ambiguous mapping of source-destination interfaces, it is forced to have the
     * same number of neighbors and registered devices. */
    /* TODO: make it possible arbitrary source-destination interface mappings. */
    assert(num_neighbors >= num_devices_registered);

    /// pcap_replaying: whole pcap file is allocated to memory & indexed before replaying starts
    if (mode == TRACE_REPLAY) {
        preprocess_pcap_file();
    }

    /* Show the configuration. */
    printf("# of CPUs = %u\n", num_cpus);
    printf("# of packets = %d\n", num_packets);
    printf("batch size = %d\n", batch_size);
    printf("packet size = %d\n", packet_size);
    printf("min. packet size = %d\n", min_packet_size);
    printf("# of flows = %d\n", num_flows);
    printf("randomize flows = %d\n", randomize_flows);
    printf("ip version = %d\n", ip_version);
    printf("latency measure = %d\n", latency_measure);
    if (latency_record) {
        printf("  recording histogram using prefix \"%s\"\n", latency_record_prefix);
    }
    printf("loop count = %d\n", loop_count);
    printf("offered throughput = %.2f Gbps\n", offered_throughput);
    printf("time limit = %u\n", time_limit);

    printf("interfaces: ");
    for (int i = 0; i < num_devices_registered; i++) {
        if (i > 0)
            printf(", ");
        //char if_name[IF_NAMESIZE];
        //if_indextoname(devices[devices_registered[i]].if_index, if_name);
        //printf("%s", if_name);
        printf("%s.%d", devices[devices_registered[i]].driver_name, devices_registered[i]);
    }
    printf("\n");
    printf("----------\n");

    /* Initialize devices and queues. */
    printf("Initializing interfaces...\n");

    unsigned num_rxq_per_port[PS_MAX_NODES];
    unsigned num_txq_per_port[PS_MAX_NODES];
    memset(num_rxq_per_port, 0, sizeof(unsigned) * PS_MAX_NODES);
    memset(num_txq_per_port, 0, sizeof(unsigned) * PS_MAX_NODES);
    unsigned num_rx_desc = 512;
    unsigned num_tx_desc = 512;

    for (int i = 0; i < num_devices_registered; i++) {
        int c;
        RTE_LCORE_FOREACH(c) {
            if (ps_in_samenode(c, i)) {
                int node_id = numa_node_of_cpu(c);
                num_rxq_per_port[node_id] ++;
                num_txq_per_port[node_id] ++;
            }
        }
    }

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode    = ETH_MQ_RX_RSS;
    uint8_t hash_key[40];
    for (unsigned k = 0; k < sizeof(hash_key); k++)
        hash_key[k] = (uint8_t) rand();
    port_conf.rx_adv_conf.rss_conf.rss_key = hash_key;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
    port_conf.txmode.mq_mode    = ETH_MQ_TX_NONE;
    port_conf.fdir_conf.mode    = RTE_FDIR_MODE_NONE;
    port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    port_conf.fdir_conf.status  = RTE_FDIR_NO_REPORT_STATUS;

    struct rte_eth_rxconf rx_conf;
    memset(&rx_conf, 0, sizeof(rx_conf));
    rx_conf.rx_thresh.pthresh = 8;
    rx_conf.rx_thresh.hthresh = 4;
    rx_conf.rx_thresh.wthresh = 4;
    rx_conf.rx_free_thresh = 32;
    rx_conf.rx_drop_en     = 0; /* when enabled, drop packets if no descriptors are available */

    struct rte_eth_txconf tx_conf;
    memset(&tx_conf, 0, sizeof(tx_conf));
    tx_conf.tx_thresh.pthresh = 36;
    tx_conf.tx_thresh.hthresh = 4;
    tx_conf.tx_thresh.wthresh = 0;
    /* The following rs_thresh and flag value enables "simple TX" function. */
    tx_conf.tx_rs_thresh   = 32;
    tx_conf.tx_free_thresh = 0;  /* use PMD default value */
    tx_conf.txq_flags      = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS;

    const uint32_t num_mp_cache = 250;
    const uint32_t num_mbufs = num_rx_desc + num_tx_desc
                               + (num_cpus * num_mp_cache)
                               + batch_size + 1;
    const uint16_t mbuf_size = (RTE_PKTMBUF_HEADROOM + ETHER_MAX_LEN);

    struct rte_mempool* rx_mempools[PS_MAX_DEVICES][PS_MAX_QUEUES];
    struct rte_mempool* tx_mempools[PS_MAX_DEVICES][PS_MAX_QUEUES];
    memset(rx_mempools, 0, sizeof(struct rte_mempool*) * PS_MAX_DEVICES * PS_MAX_QUEUES);
    memset(tx_mempools, 0, sizeof(struct rte_mempool*) * PS_MAX_DEVICES * PS_MAX_QUEUES);

    for (int i = 0; i < num_devices_registered; i++) {
        struct rte_eth_link link_info;
        int port_idx = devices_registered[i];
        int ring_idx;
        int node_idx = devices[port_idx].pci_dev->numa_node;
        assert(0 == rte_eth_dev_configure(port_idx, num_rxq_per_port[node_idx], num_txq_per_port[node_idx], &port_conf));

        /* Initialize TX queues. */
        for (ring_idx = 0; ring_idx < num_txq_per_port[node_idx]; ring_idx++) {
            struct rte_mempool *mp = NULL;
            char mempool_name[RTE_MEMPOOL_NAMESIZE];
            snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE,
                     "txmp_n%u_d%u_r%u", node_idx, port_idx, ring_idx);
            mp = rte_pktmbuf_pool_create(mempool_name, num_mbufs, num_mp_cache,
                                         0, mbuf_size, node_idx);
            if (mp == NULL)
                rte_exit(EXIT_FAILURE, "cannot allocate memory pool for txq %u:%u@%u.\n",
                         port_idx, ring_idx, node_idx);
            tx_mempools[port_idx][ring_idx] = mp;

            ret = rte_eth_tx_queue_setup(port_idx, ring_idx, num_tx_desc, node_idx, &tx_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d, qidx=%d\n",
                         ret, port_idx, ring_idx);
        }

        /* Initialize RX queues. */
        /* They are used only when latency measure is enabled,
         * but they must be initialized always. */
        for (int ring_idx = 0; ring_idx < num_rxq_per_port[node_idx]; ring_idx++) {
            struct rte_mempool *mp = NULL;
            char mempool_name[RTE_MEMPOOL_NAMESIZE];
            snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE,
                     "rxmp_n%u_d%u_r%u", node_idx, port_idx, ring_idx);

            mp = rte_pktmbuf_pool_create(mempool_name, num_mbufs, num_mp_cache,
                                         0, mbuf_size, node_idx);
            if (mp == NULL)
                rte_exit(EXIT_FAILURE, "cannot allocate memory pool for rxq %u:%u@%u.\n",
                         port_idx, ring_idx, node_idx);
            ret = rte_eth_rx_queue_setup(port_idx, ring_idx, num_rx_desc,
                                         node_idx, &rx_conf, mp);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d, qidx=%d\n",
                         ret, port_idx, ring_idx);
            rx_mempools[port_idx][ring_idx] = mp;
        }

        assert(0 == rte_eth_dev_start(port_idx));
        rte_eth_promiscuous_enable(port_idx);
        rte_eth_link_get(port_idx, &link_info);
        RTE_LOG(INFO, MAIN, "port %u -- link running at %s %s, %s\n", port_idx,
                (link_info.link_speed == ETH_LINK_SPEED_10000) ? "10G" : "lower than 10G",
                (link_info.link_duplex == ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex",
                (link_info.link_status == 1) ? "UP" : "DOWN");

        struct rte_eth_fc_conf fc_conf;
        memset(&fc_conf, 0, sizeof(fc_conf));
        rte_eth_dev_flow_ctrl_get(port_idx, &fc_conf);
        RTE_LOG(INFO, MAIN, "port %u -- flow control mode: %d, autoneg: %d\n", port_idx,
                fc_conf.mode, fc_conf.autoneg);
    }

    /* Initialize contexts. */
    printf("Initializing thread contexts...\n");

    rte_timer_subsystem_init();
    memset(contexts, 0, sizeof(struct pspgen_context *) * PS_MAX_CPUS);

    int used_cores_per_node[PS_MAX_NODES];
    memset(used_cores_per_node, 0, sizeof(int) * PS_MAX_NODES);

    unsigned my_cpu;
    RTE_LCORE_FOREACH(my_cpu) {
        int node_id = numa_node_of_cpu(my_cpu);
        struct pspgen_context *ctx = rte_malloc_socket("pspgen_context", sizeof(struct pspgen_context),
                                                       RTE_CACHE_LINE_SIZE, node_id);
        assert(ctx != NULL);
        memset(ctx, 0, sizeof(struct pspgen_context));
        contexts[my_cpu] = ctx;

        ctx->mode = mode;

        ctx->num_cpus = num_cpus;
        ctx->my_node  = node_id;
        ctx->my_cpu   = my_cpu;
        ctx->tsc_hz   = rte_get_tsc_hz();

        ctx->num_txq_per_port = num_txq_per_port[node_id];
        ctx->ring_idx   = used_cores_per_node[node_id];
        ctx->num_attached_ports = 0;
        for (int i = 0; i < num_devices_registered; i++) {
            int port_idx = devices_registered[i];
            if (ps_in_samenode(ctx->my_cpu, port_idx)) {
                ctx->attached_ports[ctx->num_attached_ports ++] = port_idx;
                printf("  core %d (node %d) uses port:ring %d:%d\n", my_cpu, node_id, port_idx, ctx->ring_idx);
                ctx->tx_mempools[port_idx] = tx_mempools[port_idx][ctx->ring_idx];
            }
        }

        ctx->num_packets     = num_packets ? : LONG_MAX;
        ctx->batch_size      = batch_size;
        ctx->packet_size     = packet_size;
        ctx->min_packet_size = min_packet_size;
        ctx->ip_version      = ip_version;
        ctx->num_flows       = num_flows;
        ctx->loop_count      = loop_count;
        ctx->begin           = begin_datetime;
        ctx->time_limit      = time_limit;
        ctx->offered_throughput = offered_throughput;

        ctx->latency_measure = latency_measure;
        ctx->latency_record  = latency_record;
        ctx->latency_log     = NULL;  /* opened in send_packets() */
        strncpy(ctx->latency_record_prefix, latency_record_prefix, MAX_PATH);
        ctx->magic_number    = my_cpu;

        used_cores_per_node[node_id] ++;
    }

    /* Spawn threads and send packets. */
    if (num_flows > 0)
        srand(time(NULL));

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Running...\n");
    printf("----------\n");

    begin = ps_get_usec();
    rte_eal_mp_remote_launch(send_packets, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();
    end = ps_get_usec();

    if (mode == TRACE_REPLAY) {
        if (pcap_alloc_file != 0) {
            free(pcap_alloc_file);
            pcap_alloc_file = 0;
        }
    }

    printf("----------\n");
    printf("%.2f seconds elapsed\n", (end - begin) / 1000000.0);
    return 0;
}

/* vim: set ts=8 sts=4 sw=4 et: */
