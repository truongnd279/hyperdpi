#include "flow_table.h"

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <string.h>

struct flow_table {
    struct rte_hash *hash;
    struct flow_entry *entries;
    uint32_t max_entries;
    uint32_t count;
};

struct flow_table *flow_table_create(uint32_t max_entries)
{
    struct flow_table *ft = rte_zmalloc("flow_table", sizeof(*ft), 0);
    if (!ft) return NULL;

    struct rte_hash_parameters hp = {
        .name = "flow_hash",
        .entries = max_entries,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    ft->hash = rte_hash_create(&hp);
    if (!ft->hash) {
        rte_free(ft);
        return NULL;
    }

    ft->entries = rte_zmalloc("flow_entries",
        max_entries * sizeof(struct flow_entry), 0);
    if (!ft->entries) {
        rte_hash_free(ft->hash);
        rte_free(ft);
        return NULL;
    }

    ft->max_entries = max_entries;
    ft->count = 0;
    return ft;
}

void flow_table_destroy(struct flow_table *ft)
{
    if (!ft) return;
    rte_hash_free(ft->hash);
    rte_free(ft->entries);
    rte_free(ft);
}

struct flow_entry *flow_table_lookup(struct flow_table *ft,
                                     const struct flow_key *key)
{
    int32_t ret = rte_hash_lookup(ft->hash, key);
    if (ret < 0) return NULL;
    return &ft->entries[ret];
}

struct flow_entry *flow_table_insert(struct flow_table *ft,
                                     const struct flow_key *key)
{
    int32_t ret = rte_hash_add_key(ft->hash, key);
    if (ret < 0) return NULL;
    struct flow_entry *fe = &ft->entries[ret];
    fe->key = *key;
    fe->first_seen = rte_rdtsc();
    fe->last_seen = fe->first_seen;
    fe->packet_count = 0;
    fe->byte_count = 0;
    fe->app_protocol_id = 0;
    fe->state = 1;
    ft->count++;
    return fe;
}

void flow_table_update_stats(struct flow_table *ft,
                             const struct flow_key *key, uint64_t pkt_len)
{
    struct flow_entry *fe = flow_table_lookup(ft, key);
    if (!fe)
        fe = flow_table_insert(ft, key);
    if (fe) {
        fe->packet_count++;
        fe->byte_count += pkt_len;
        fe->last_seen = rte_rdtsc();
    }
}

void flow_table_cleanup(struct flow_table *ft, uint32_t timeout_sec)
{
    uint64_t now = rte_rdtsc();
    uint64_t timeout_cycles = (uint64_t)timeout_sec * rte_get_tsc_hz();

    for (uint32_t i = 0; i < ft->max_entries; i++) {
        if (ft->entries[i].state) {
            if (now - ft->entries[i].last_seen > timeout_cycles) {
                ft->entries[i].state = 0;
                rte_hash_del_key(ft->hash, &ft->entries[i].key);
                ft->count--;
            }
        }
    }
}

void flow_table_extract_key(const struct rte_mbuf *mbuf,
                            struct flow_key *key)
{
    memset(key, 0, sizeof(*key));

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        key->src_ip = ip->src_addr;
        key->dst_ip = ip->dst_addr;
        key->proto = ip->next_proto_id;

        if (key->proto == FLOW_PROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)
                ((unsigned char *)ip + (ip->version_ihl & 0x0f) * 4);
            key->src_port = tcp->src_port;
            key->dst_port = tcp->dst_port;
        } else if (key->proto == FLOW_PROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)
                ((unsigned char *)ip + (ip->version_ihl & 0x0f) * 4);
            key->src_port = udp->src_port;
            key->dst_port = udp->dst_port;
        }
    }
}
