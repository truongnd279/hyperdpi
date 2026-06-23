#ifndef HYPERDPI_WORKER_THREAD_H
#define HYPERDPI_WORKER_THREAD_H

#include <rte_launch.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#include "flow_table.h"
#include "hyperscan_engine.h"

struct worker_thread_config {
    unsigned worker_id;
    unsigned lcore_id;
    struct rte_ring *rx_ring;
    struct rte_ring *tx_ring;
    struct rte_mempool *pool;
    struct flow_table *ft;
    struct hs_engine *hs;
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t packets_matched;
};

int worker_thread_proc(void *arg);

#endif /* HYPERDPI_WORKER_THREAD_H */
