#include "tx_thread.h"
#include "app_config.h"

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_pause.h>

extern volatile int g_quit;

int tx_thread_proc(void *arg)
{
    struct tx_thread_config *cfg = (struct tx_thread_config *)arg;

    RTE_LOG(INFO, USER1, "TX thread started on lcore %u, port %u\n",
            cfg->lcore_id, cfg->port_id);

    struct rte_mbuf *pkts[MAX_BURST_SIZE];
    cfg->packets_sent = 0;
    cfg->packets_dropped = 0;

    while (!g_quit) {
        uint16_t burst = cfg->burst_size;
        if (burst > MAX_BURST_SIZE) burst = MAX_BURST_SIZE;
        uint16_t nb_pkts = rte_ring_dequeue_burst(cfg->tx_ring, (void **)pkts,
                                                   burst, NULL);
        if (nb_pkts == 0) {
            rte_pause();
            continue;
        }

        uint16_t nb_tx = rte_eth_tx_burst(cfg->port_id, 0, pkts, nb_pkts);

        __atomic_add_fetch(&cfg->packets_sent, nb_tx, __ATOMIC_RELAXED);

        if (nb_tx < nb_pkts) {
            __atomic_add_fetch(&cfg->packets_dropped, (nb_pkts - nb_tx), __ATOMIC_RELAXED);
            for (uint16_t i = nb_tx; i < nb_pkts; i++) {
                rte_pktmbuf_free(pkts[i]);
            }
        }
    }

    return 0;
}
