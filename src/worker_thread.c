#include "worker_thread.h"

#include <rte_log.h>
#include <rte_pause.h>

#define BURST_DEQUEUE 32

int worker_thread_proc(void *arg)
{
    struct worker_thread_config *cfg = (struct worker_thread_config *)arg;

    RTE_LOG(INFO, USER1, "Worker %u started on lcore %u\n",
            cfg->worker_id, cfg->lcore_id);

    struct rte_mbuf *pkts[BURST_DEQUEUE];
    cfg->packets_processed = 0;
    cfg->bytes_processed = 0;
    cfg->packets_matched = 0;

    while (1) {
        uint16_t nb_pkts = rte_ring_dequeue_burst(cfg->rx_ring, (void **)pkts,
                                                   BURST_DEQUEUE, NULL);
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
            if (hs_engine_scan(cfg->hs, mbuf, &matched_id) == 0) {
                cfg->packets_matched++;

                struct flow_entry *fe = flow_table_lookup(cfg->ft, &key);
                if (fe) fe->app_protocol_id = matched_id;
            }

            cfg->packets_processed++;
            cfg->bytes_processed += pkt_len;

            if (rte_ring_enqueue(cfg->tx_ring, mbuf) != 0) {
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    return 0;
}
