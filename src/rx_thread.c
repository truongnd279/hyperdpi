#include "rx_thread.h"
#include "flow_table.h"
#include "app_config.h"

#include <rte_ethdev.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_pause.h>
#include <string.h>

extern volatile int g_quit;

#define RX_STAGE_SIZE MAX_BURST_SIZE

int rx_thread_proc(void *arg)
{
    struct rx_thread_config *cfg = (struct rx_thread_config *)arg;

    RTE_LOG(INFO, USER1, "RX thread started on lcore %u, port %u\n",
            cfg->lcore_id, cfg->port_id);

    struct rte_mbuf *pkts_burst[MAX_BURST_SIZE];
    uint64_t total_pkts = 0;

    while (!g_quit) {
        uint16_t burst = cfg->burst_size;
        if (burst > MAX_BURST_SIZE) burst = MAX_BURST_SIZE;
        uint16_t nb_rx = rte_eth_rx_burst(cfg->port_id, 0,
                                          pkts_burst, burst);
        if (nb_rx == 0) {
            rte_pause();
            continue;
        }

        total_pkts += nb_rx;

        /* Stage packets per worker for burst enqueue */
        struct rte_mbuf *staged[MAX_WORKERS][RX_STAGE_SIZE];
        uint16_t staged_count[MAX_WORKERS];
        memset(staged_count, 0, sizeof(staged_count));

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = pkts_burst[i];

            struct flow_key key;
            flow_table_extract_key(mbuf, &key);

            uint32_t hash = rte_jhash(&key, sizeof(key), 0);
            int worker_id = hash % cfg->nb_workers;

            staged[worker_id][staged_count[worker_id]++] = mbuf;
        }

        /* Flush each worker's batch */
        for (int w = 0; w < cfg->nb_workers; w++) {
            if (staged_count[w] == 0) continue;

            uint16_t n = rte_ring_enqueue_burst(
                cfg->worker_rings[w],
                (void **)staged[w],
                staged_count[w], NULL);

            /* Free any packets that could not be enqueued */
            for (uint16_t i = n; i < staged_count[w]; i++) {
                rte_pktmbuf_free(staged[w][i]);
            }
        }
    }

    return 0;
}
