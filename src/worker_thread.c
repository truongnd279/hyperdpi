#include "worker_thread.h"
#include "app_config.h"

#include <rte_log.h>
#include <rte_pause.h>

extern volatile int g_quit;

int worker_thread_proc(void *arg)
{
    struct worker_thread_config *cfg = (struct worker_thread_config *)arg;

    RTE_LOG(INFO, USER1, "Worker %u started on lcore %u\n",
            cfg->worker_id, cfg->lcore_id);

    struct rte_mbuf *pkts[MAX_BURST_SIZE];
    __atomic_store_n(&cfg->packets_processed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->bytes_processed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->packets_matched, 0, __ATOMIC_RELAXED);

    while (!g_quit) {
        uint16_t burst = MAX_BURST_SIZE;
        uint16_t nb_pkts = rte_ring_dequeue_burst(cfg->rx_ring, (void **)pkts,
                                                   burst, NULL);
        if (nb_pkts == 0) {
            rte_pause();
            continue;
        }

        for (uint16_t i = 0; i < nb_pkts; i++) {
            struct rte_mbuf *mbuf = pkts[i];
            uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

            struct flow_key key;
            flow_table_extract_key(mbuf, &key);
            flow_table_update_stats(cfg->ft, &key, pkt_len);

            unsigned int matched_id;
            if (hs_engine_scan(cfg->hs, mbuf, &matched_id, cfg->scratch) == 0) {
                __atomic_add_fetch(&cfg->packets_matched, 1, __ATOMIC_RELAXED);

                struct flow_entry *fe = flow_table_lookup(cfg->ft, &key);
                if (fe) fe->app_protocol_id = matched_id;
            }

            __atomic_add_fetch(&cfg->packets_processed, 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&cfg->bytes_processed, pkt_len, __ATOMIC_RELAXED);

            if (rte_ring_enqueue(cfg->tx_ring, mbuf) != 0) {
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    return 0;
}
