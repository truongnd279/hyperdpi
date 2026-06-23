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
        .extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD,
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
    uint8_t expected = 0;
    if (__atomic_compare_exchange_n(&fe->state, &expected, 1,
                                    false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        fe->key = *key;
        fe->first_seen = rte_rdtsc();
        fe->last_seen = fe->first_seen;
        fe->packet_count = 0;
        fe->byte_count = 0;
        fe->app_protocol_id = 0;
        __atomic_add_fetch(&ft->count, 1, __ATOMIC_RELAXED);
    }
    return fe;
}

void flow_table_update_stats(struct flow_table *ft,
                             const struct flow_key *key, uint64_t pkt_len)
{
    struct flow_entry *fe = flow_table_lookup(ft, key);
    if (!fe)
        fe = flow_table_insert(ft, key);
    if (fe) {
        __atomic_add_fetch(&fe->packet_count, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&fe->byte_count, pkt_len, __ATOMIC_RELAXED);
        __atomic_store_n(&fe->last_seen, rte_rdtsc(), __ATOMIC_RELAXED);
    }
}

void flow_table_cleanup(struct flow_table *ft, uint32_t timeout_sec)
{
    uint64_t now = rte_rdtsc();
    uint64_t timeout_cycles = (uint64_t)timeout_sec * rte_get_tsc_hz();

    for (uint32_t i = 0; i < ft->max_entries; i++) {
        if (__atomic_load_n(&ft->entries[i].state, __ATOMIC_RELAXED)) {
            uint64_t last = __atomic_load_n(&ft->entries[i].last_seen, __ATOMIC_RELAXED);
            uint64_t age = (now >= last) ? now - last : UINT64_MAX - last + now;
            if (age > timeout_cycles) {
                __atomic_store_n(&ft->entries[i].state, 0, __ATOMIC_RELAXED);
                rte_hash_del_key(ft->hash, &ft->entries[i].key);
                __atomic_sub_fetch(&ft->count, 1, __ATOMIC_RELAXED);
            }
        }
    }
}

void flow_table_extract_key(const struct rte_mbuf *mbuf,
                            struct flow_key *key)
{
    memset(key, 0, sizeof(*key));

    uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);
    char *p = rte_pktmbuf_mtod(mbuf, char *);
    uint32_t offset = 0;

    if (pkt_len < sizeof(struct rte_ether_hdr)) return;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    offset += sizeof(struct rte_ether_hdr);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    /* Skip VLAN tags (single or QinQ) */
    while (ether_type == RTE_ETHER_TYPE_VLAN || ether_type == RTE_ETHER_TYPE_QINQ) {
        if (pkt_len < offset + sizeof(struct rte_vlan_hdr)) return;
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(p + offset);
        offset += sizeof(struct rte_vlan_hdr);
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
    }

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        if (pkt_len < offset + sizeof(struct rte_ipv4_hdr)) return;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(p + offset);
        key->src_ip = ip->src_addr;
        key->dst_ip = ip->dst_addr;
        key->proto = ip->next_proto_id;

        uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) * 4;
        if (ip_hdr_len < sizeof(struct rte_ipv4_hdr)) return;
        uint32_t l4_off = offset + ip_hdr_len;

        if (key->proto == FLOW_PROTO_TCP) {
            if (pkt_len < l4_off + sizeof(struct rte_tcp_hdr)) return;
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(p + l4_off);
            key->src_port = tcp->src_port;
            key->dst_port = tcp->dst_port;
        } else if (key->proto == FLOW_PROTO_UDP) {
            if (pkt_len < l4_off + sizeof(struct rte_udp_hdr)) return;
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(p + l4_off);
            key->src_port = udp->src_port;
            key->dst_port = udp->dst_port;
        }
    } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        if (pkt_len < offset + sizeof(struct rte_ipv6_hdr)) return;
        struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(p + offset);
        const uint32_t *s6 = (const uint32_t *)ip6->src_addr;
        const uint32_t *d6 = (const uint32_t *)ip6->dst_addr;
        key->src_ip = s6[0] ^ s6[1] ^ s6[2] ^ s6[3];
        key->dst_ip = d6[0] ^ d6[1] ^ d6[2] ^ d6[3];
        key->proto = ip6->proto;
        uint32_t l4_off = offset + sizeof(struct rte_ipv6_hdr);
        if (key->proto == FLOW_PROTO_TCP) {
            if (pkt_len < l4_off + sizeof(struct rte_tcp_hdr)) return;
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(p + l4_off);
            key->src_port = tcp->src_port;
            key->dst_port = tcp->dst_port;
        } else if (key->proto == FLOW_PROTO_UDP) {
            if (pkt_len < l4_off + sizeof(struct rte_udp_hdr)) return;
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(p + l4_off);
            key->src_port = udp->src_port;
            key->dst_port = udp->dst_port;
        }
    }
}
