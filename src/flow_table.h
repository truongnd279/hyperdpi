#ifndef HYPERDPI_FLOW_TABLE_H
#define HYPERDPI_FLOW_TABLE_H

#include <stdint.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define FLOW_PROTO_TCP     6
#define FLOW_PROTO_UDP     17

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} __attribute__((packed));

struct flow_entry {
    struct flow_key key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t first_seen;
    uint64_t last_seen;
    uint32_t app_protocol_id;
    uint8_t  state;
};

struct flow_table;

struct flow_table *flow_table_create(uint32_t max_entries);
void flow_table_destroy(struct flow_table *ft);
uint32_t flow_table_count(struct flow_table *ft);

struct flow_entry *flow_table_lookup(struct flow_table *ft, const struct flow_key *key);
struct flow_entry *flow_table_insert(struct flow_table *ft, const struct flow_key *key);
void flow_table_update_stats(struct flow_table *ft, const struct flow_key *key,
                             uint64_t pkt_len);
void flow_table_cleanup(struct flow_table *ft, uint32_t timeout_sec);

void flow_table_extract_key(const struct rte_mbuf *mbuf, struct flow_key *key);

#endif /* HYPERDPI_FLOW_TABLE_H */
