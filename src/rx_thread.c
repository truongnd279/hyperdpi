#include "rx_thread.h"
#include "flow_table.h"

#include <rte_ethdev.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_pause.h>

int rx_thread_proc(void *arg)
{
    struct rx_thread_config *cfg = (struct rx_thread_config *)arg;

    RTE_LOG(INFO, USER1, "RX thread started on lcore %u, port %u\n",
            cfg->lcore_id, cfg->port_id);

    struct rte_mbuf *pkts_burst[cfg->burst_size];
    uint64_t total_pkts = 0;

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(cfg->port_id, 0,
                                          pkts_burst, cfg->burst_size);
        if (nb_rx == 0) {
            rte_pause();
            continue;
        }

        total_pkts += nb_rx;

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = pkts_burst[i];

            struct flow_key key;
            flow_table_extract_key(mbuf, &key);

            uint32_t hash = rte_jhash(&key, sizeof(key), 0);
            int worker_id = hash % cfg->nb_workers;

            if (rte_ring_enqueue(cfg->worker_rings[worker_id], mbuf) != 0) {
                rte_pktmbuf_free(mbuf);
            }
        }

        if (total_pkts % 1000000 == 0) {
            RTE_LOG(DEBUG, USER1, "RX: %lu packets received\n", total_pkts);
        }
    }

    return 0;
}
