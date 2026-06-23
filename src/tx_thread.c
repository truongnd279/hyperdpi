#include "tx_thread.h"

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_pause.h>

#define BURST_DEQUEUE 64

int tx_thread_proc(void *arg)
{
    struct tx_thread_config *cfg = (struct tx_thread_config *)arg;

    RTE_LOG(INFO, USER1, "TX thread started on lcore %u, port %u\n",
            cfg->lcore_id, cfg->port_id);

    struct rte_mbuf *pkts[BURST_DEQUEUE];
    cfg->packets_sent = 0;
    cfg->packets_dropped = 0;

    while (1) {
        uint16_t nb_pkts = rte_ring_dequeue_burst(cfg->tx_ring, (void **)pkts,
                                                   BURST_DEQUEUE, NULL);
        if (nb_pkts == 0) {
            rte_pause();
            continue;
        }

        uint16_t nb_tx = rte_eth_tx_burst(cfg->port_id, 0, pkts, nb_pkts);

        cfg->packets_sent += nb_tx;

        if (nb_tx < nb_pkts) {
            cfg->packets_dropped += (nb_pkts - nb_tx);
            for (uint16_t i = nb_tx; i < nb_pkts; i++) {
                rte_pktmbuf_free(pkts[i]);
            }
        }
    }

    return 0;
}
