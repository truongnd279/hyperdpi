#include "hyperscan_engine.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

struct match_context {
    unsigned int matched_id;
    int matched;
};

static int event_handler(unsigned int id, unsigned long long from,
                         unsigned long long to, unsigned int flags,
                         void *ctx)
{
    (void)from;
    (void)to;
    (void)flags;
    struct match_context *mc = (struct match_context *)ctx;
    mc->matched = 1;
    mc->matched_id = id;
    return 1;
}

struct hs_engine *hs_engine_create(const char *rules_file, unsigned int mode)
{
    struct hs_engine *eng = rte_zmalloc("hs_engine", sizeof(*eng), 0);
    if (!eng) return NULL;

    eng->mode = mode;

    FILE *fp = fopen(rules_file, "r");
    if (!fp) {
        RTE_LOG(ERR, USER1, "Cannot open rules file: %s\n", rules_file);
        rte_free(eng);
        return NULL;
    }

    eng->rules = rte_zmalloc("hs_rules",
        MAX_PATTERNS * sizeof(struct hs_rule), 0);
    if (!eng->rules) {
        fclose(fp);
        rte_free(eng);
        return NULL;
    }

    hs_database_t *db = NULL;
    hs_compile_error_t *compile_err = NULL;
    hs_scratch_t *scratch = NULL;

    char line[MAX_RULE_LINE];
    int nb_patterns = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char pattern[512], protocol[16], desc[256];
        unsigned int id;
        if (sscanf(line, "%u,%511[^,],%15[^,],%255[^\r\n]",
                   &id, pattern, protocol, desc) < 4)
            continue;

        struct hs_rule *r = &eng->rules[eng->nb_rules];
        r->id = id;
        
        snprintf(r->pattern, sizeof(r->pattern), "%s", pattern);
        snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
        snprintf(r->description, sizeof(r->description), "%s", desc);

        size_t plen = strlen(pattern);
        if (plen >= 2 && pattern[0] == '/' && pattern[plen-1] == '/') {
            memmove(pattern, pattern + 1, plen - 2);
            pattern[plen - 2] = '\0';
        }

        hs_database_t *tmp_db = NULL;
        hs_compile_error_t *tmp_err = NULL;
        hs_compile(pattern, HS_FLAG_CASELESS, id, NULL, &tmp_db, &tmp_err);

        if (tmp_err) {
            RTE_LOG(WARNING, USER1, "Pattern %u compile error: %s\n",
                    id, tmp_err->message);
            hs_free_compile_error(tmp_err);
            continue;
        }

        if (!db) {
            db = tmp_db;
        } else {
            hs_database_t *combined = NULL;
            hs_error_t err = hs_combine_db(db, tmp_db, &combined);
            if (err == HS_SUCCESS && combined) {
                hs_free_database(db);
                db = combined;
            }
            hs_free_database(tmp_db);
        }

        eng->nb_rules++;
        nb_patterns++;
    }
    fclose(fp);

    if (!db) {
        RTE_LOG(ERR, USER1, "No valid patterns compiled\n");
        rte_free(eng->rules);
        rte_free(eng);
        return NULL;
    }

    hs_error_t err = hs_alloc_scratch(db, &scratch);
    if (err != HS_SUCCESS) {
        RTE_LOG(ERR, USER1, "Failed to allocate Hyperscan scratch\n");
        hs_free_database(db);
        rte_free(eng->rules);
        rte_free(eng);
        return NULL;
    }

    eng->db = db;
    eng->scratch = scratch;
    RTE_LOG(INFO, USER1, "Hyperscan engine: %d patterns compiled\n",
            eng->nb_rules);
    return eng;
}

hs_scratch_t *hs_engine_alloc_scratch(struct hs_engine *eng)
{
    if (!eng || !eng->scratch) return NULL;
    hs_scratch_t *s = NULL;
    hs_error_t err = hs_clone_scratch(eng->scratch, &s);
    if (err != HS_SUCCESS) return NULL;
    return s;
}

void hs_engine_destroy(struct hs_engine *eng)
{
    if (!eng) return;
    if (eng->db)      hs_free_database(eng->db);
    if (eng->scratch) hs_free_scratch(eng->scratch);
    if (eng->rules)   rte_free(eng->rules);
    rte_free(eng);
}

int hs_engine_scan(struct hs_engine *eng, const struct rte_mbuf *mbuf,
                   unsigned int *matched_id, hs_scratch_t *scratch)
{
    if (!eng || !eng->db) return -1;

    if (!scratch) scratch = eng->scratch;
    if (!scratch) return -1;

    char *payload = rte_pktmbuf_mtod(mbuf, char *);
    uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

    if (pkt_len < sizeof(struct rte_ether_hdr)) return -1;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)payload;
    uint32_t offset = sizeof(struct rte_ether_hdr);

    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    while (ether_type == RTE_ETHER_TYPE_VLAN || ether_type == RTE_ETHER_TYPE_QINQ) {
        if (pkt_len < offset + sizeof(struct rte_vlan_hdr)) return -1;
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(payload + offset);
        offset += sizeof(struct rte_vlan_hdr);
        ether_type = rte_be_to_cpu_16(vlan->eth_proto);
    }

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        if (pkt_len < offset + sizeof(struct rte_ipv4_hdr)) return -1;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(payload + offset);
        uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) * 4;
        if (ip_hdr_len < sizeof(struct rte_ipv4_hdr)) return -1;
        if (pkt_len < offset + ip_hdr_len) return -1;
        offset += ip_hdr_len;

        if (ip->next_proto_id == IPPROTO_TCP) {
            if (pkt_len < offset + sizeof(struct rte_tcp_hdr)) return -1;
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(payload + offset);
            uint32_t tcp_hdr_len = ((tcp->data_off >> 4) & 0x0f) * 4;
            if (tcp_hdr_len < sizeof(struct rte_tcp_hdr)) return -1;
            if (pkt_len < offset + tcp_hdr_len) return -1;
            offset += tcp_hdr_len;
        } else if (ip->next_proto_id == IPPROTO_UDP) {
            if (pkt_len < offset + sizeof(struct rte_udp_hdr)) return -1;
            offset += sizeof(struct rte_udp_hdr);
        }
    } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        if (pkt_len < offset + sizeof(struct rte_ipv6_hdr)) return -1;
        offset += sizeof(struct rte_ipv6_hdr);
    }

    if (offset >= pkt_len) return -1;

    uint32_t payload_len = pkt_len - offset;
    char *app_data = payload + offset;

    struct match_context mc = { .matched = 0, .matched_id = 0 };

    hs_error_t err = hs_scan(eng->db, app_data, payload_len, 0,
                             scratch, event_handler, &mc);
    if (err != HS_SUCCESS) return -1;

    if (mc.matched) {
        *matched_id = mc.matched_id;
        return 0;
    }
    return -1;
}
