#ifndef HYPERDPI_TX_THREAD_H
#define HYPERDPI_TX_THREAD_H

#include <rte_launch.h>
#include <rte_ring.h>

struct tx_thread_config {
    uint16_t port_id;
    unsigned lcore_id;
    struct rte_ring *tx_ring;
    uint16_t burst_size;
    uint64_t packets_sent;
    uint64_t packets_dropped;
};

int tx_thread_proc(void *arg);

#endif /* HYPERDPI_TX_THREAD_H */
