#include "hyperscan_engine.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rte_malloc.h>
#include <rte_log.h>

struct match_context {
    unsigned int matched_id;
    int matched;
    int action;
    struct hs_engine *eng;
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
    if (id < (unsigned int)mc->eng->nb_rules)
        mc->action = mc->eng->rules[id].action;
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

    char *patterns[MAX_PATTERNS];
    unsigned int flags[MAX_PATTERNS];
    unsigned int ids[MAX_PATTERNS];
    int valid_count = 0;

    char line[MAX_RULE_LINE];

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        char traffic_type[16], pattern[512], action_str[16];
        if (sscanf(line, "%15[^,],%511[^,],%15[^\r\n]",
                   traffic_type, pattern, action_str) < 3)
            continue;

        int action = HS_ACTION_FORWARD;
        if (strcmp(action_str, "DROP") == 0)
            action = HS_ACTION_DROP;

        struct hs_rule *r = &eng->rules[eng->nb_rules];
        r->id = eng->nb_rules;
        snprintf(r->pattern, sizeof(r->pattern), "%s", pattern);
        snprintf(r->traffic_type, sizeof(r->traffic_type), "%s", traffic_type);
        r->action = action;

        patterns[valid_count] = r->pattern;
        flags[valid_count] = HS_FLAG_CASELESS;
        ids[valid_count] = eng->nb_rules;
        valid_count++;
        eng->nb_rules++;
    }
    fclose(fp);

    if (valid_count == 0) {
        RTE_LOG(ERR, USER1, "No valid patterns found\n");
        rte_free(eng->rules);
        rte_free(eng);
        return NULL;
    }

    hs_database_t *db = NULL;
    hs_compile_error_t *compile_err = NULL;
    hs_error_t err = hs_compile_multi(
        (const char *const *)patterns,
        flags, ids, valid_count, mode, NULL,
        &db, &compile_err);

    if (compile_err) {
        RTE_LOG(ERR, USER1, "Pattern compilation failed at index %u: %s\n",
                compile_err->expression, compile_err->message);
        hs_free_compile_error(compile_err);
        rte_free(eng->rules);
        rte_free(eng);
        return NULL;
    }

    if (err != HS_SUCCESS) {
        RTE_LOG(ERR, USER1, "hs_compile_multi failed: %d\n", err);
        rte_free(eng->rules);
        rte_free(eng);
        return NULL;
    }

    hs_scratch_t *scratch = NULL;
    err = hs_alloc_scratch(db, &scratch);
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

int hs_engine_scan(struct hs_engine *eng, const char *data, unsigned int len,
                   struct hs_match_result *result, hs_scratch_t *scratch)
{
    if (!eng || !eng->db || !result) return -1;

    if (!scratch) scratch = eng->scratch;
    if (!scratch) return -1;

    struct match_context mc = {
        .matched = 0,
        .matched_id = 0,
        .action = HS_ACTION_FORWARD,
        .eng = eng,
    };

    hs_error_t err = hs_scan(eng->db, data, len, 0,
                             scratch, event_handler, &mc);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED)
        return -1;

    result->matched = mc.matched;
    result->rule_id = mc.matched_id;
    result->action = mc.action;
    return mc.matched ? 0 : -1;
}
