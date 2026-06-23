#ifndef HYPERDPI_HYPERSCAN_ENGINE_H
#define HYPERDPI_HYPERSCAN_ENGINE_H

#include <hs/hs.h>
#include <stdint.h>

#define MAX_PATTERNS       4096
#define MAX_RULE_LINE      1024

#define HS_ACTION_FORWARD  0
#define HS_ACTION_DROP     1

struct hs_rule {
    unsigned int id;
    char pattern[512];
    char traffic_type[16];
    int action;
};

struct hs_match_result {
    int matched;
    unsigned int rule_id;
    int action;
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

hs_scratch_t *hs_engine_alloc_scratch(struct hs_engine *eng);

int hs_engine_scan(struct hs_engine *eng, const char *data, unsigned int len,
                   struct hs_match_result *result, hs_scratch_t *scratch);

#endif /* HYPERDPI_HYPERSCAN_ENGINE_H */
