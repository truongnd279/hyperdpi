#ifndef HYPERDPI_HYPERSCAN_ENGINE_H
#define HYPERDPI_HYPERSCAN_ENGINE_H

#include <hs/hs.h>
#include <rte_mbuf.h>

#define MAX_PATTERNS       4096
#define MAX_RULE_LINE      1024

struct hs_rule {
    unsigned int id;
    char pattern[512];
    char protocol[16];
    char description[256];
};

struct hs_engine {
    hs_database_t *db;
    hs_scratch_t  *scratch;
    struct hs_rule *rules;
    int nb_rules;
    unsigned int mode;
};

struct hs_engine *hs_engine_create(const char *rules_file, unsigned int mode);
void hs_engine_destroy(struct hs_engine *eng);

int hs_engine_scan(struct hs_engine *eng, const struct rte_mbuf *mbuf,
                   unsigned int *matched_id);

#endif /* HYPERDPI_HYPERSCAN_ENGINE_H */
