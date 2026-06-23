#ifndef HYPERDPI_RX_THREAD_H
#define HYPERDPI_RX_THREAD_H

#include <rte_launch.h>
#include <rte_ring.h>
#include <rte_mempool.h>

struct rx_thread_config {
    uint16_t port_id;
    unsigned lcore_id;
    struct rte_ring **worker_rings;
    int nb_workers;
    struct rte_mempool *pool;
    uint16_t burst_size;
};

int rx_thread_proc(void *arg);

#endif /* HYPERDPI_RX_THREAD_H */
