#ifndef HYPERDPI_STATS_THREAD_H
#define HYPERDPI_STATS_THREAD_H

#include <rte_launch.h>

#include "flow_table.h"
#include "worker_thread.h"

struct stats_thread_config {
    unsigned lcore_id;
    struct flow_table *ft;
    struct worker_thread_config *worker_cfgs;
    int nb_workers;
    uint64_t *tx_sent;
    uint64_t *tx_dropped;
    uint32_t interval_sec;
};

int stats_thread_proc(void *arg);

#endif /* HYPERDPI_STATS_THREAD_H */
