#include "stats_thread.h"
#include "app_config.h"

#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <stdio.h>

int stats_thread_proc(void *arg)
{
    struct stats_thread_config *cfg = (struct stats_thread_config *)arg;

    RTE_LOG(INFO, USER1, "Stats thread started on lcore %u\n",
            cfg->lcore_id);

    uint64_t prev_worker_pkts[MAX_WORKERS];
    uint64_t prev_worker_bytes[MAX_WORKERS];
    uint64_t prev_worker_matched[MAX_WORKERS];
    uint64_t prev_tx_sent = 0;
    uint64_t prev_tx_dropped = 0;

    for (int i = 0; i < cfg->nb_workers; i++) {
        prev_worker_pkts[i] = cfg->worker_cfgs[i].packets_processed;
        prev_worker_bytes[i] = cfg->worker_cfgs[i].bytes_processed;
        prev_worker_matched[i] = cfg->worker_cfgs[i].packets_matched;
    }

    uint64_t iter = 0;

    while (1) {
        rte_delay_us(cfg->interval_sec * 1000000);
        iter++;

        uint64_t total_pkts = 0, total_bytes = 0, total_matched = 0;

        printf("\n========== HyperDPI Stats [%lu] ==========\n", iter);

        for (int i = 0; i < cfg->nb_workers; i++) {
            uint64_t dp = cfg->worker_cfgs[i].packets_processed - prev_worker_pkts[i];
            uint64_t db = cfg->worker_cfgs[i].bytes_processed - prev_worker_bytes[i];
            uint64_t dm = cfg->worker_cfgs[i].packets_matched - prev_worker_matched[i];

            total_pkts += dp;
            total_bytes += db;
            total_matched += dm;

            printf("Worker %d: %lu pkts, %lu bytes, %lu matched\n",
                   i, dp, db, dm);

            prev_worker_pkts[i] = cfg->worker_cfgs[i].packets_processed;
            prev_worker_bytes[i] = cfg->worker_cfgs[i].bytes_processed;
            prev_worker_matched[i] = cfg->worker_cfgs[i].packets_matched;
        }

        uint64_t tx_sent = *cfg->tx_sent - prev_tx_sent;
        uint64_t tx_dropped = *cfg->tx_dropped - prev_tx_dropped;

        printf("TX: %lu sent, %lu dropped\n", tx_sent, tx_dropped);
        printf("Total: %lu pkts, %lu bytes, %lu matched\n",
               total_pkts, total_bytes, total_matched);

        if (cfg->interval_sec > 0 && total_pkts > 0) {
            double mbps = (double)total_bytes * 8.0 /
                          (cfg->interval_sec * 1000000.0);
            printf("Throughput: %.2f Mbps\n", mbps);
        }

        printf("=========================================\n");
        fflush(stdout);

        prev_tx_sent = *cfg->tx_sent;
        prev_tx_dropped = *cfg->tx_dropped;

        flow_table_cleanup(cfg->ft, cfg->interval_sec);
    }

    return 0;
}
