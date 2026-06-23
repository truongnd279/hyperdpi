#include "stats_thread.h"
#include "app_config.h"

#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

extern volatile int g_quit;

static double calc_mbps(uint64_t bytes, uint32_t sec)
{
    if (sec == 0) return 0.0;
    return (double)bytes * 8.0 / (sec * 1000000.0);
}

int stats_thread_proc(void *arg)
{
    struct stats_thread_config *cfg = (struct stats_thread_config *)arg;

    RTE_LOG(INFO, USER1, "Stats thread started on lcore %u\n",
            cfg->lcore_id);

    uint64_t prev_worker_pkts[MAX_WORKERS] = {0};
    uint64_t prev_worker_bytes[MAX_WORKERS] = {0};
    uint64_t prev_worker_matched[MAX_WORKERS] = {0};
    uint64_t prev_tx_sent = 0;
    uint64_t prev_tx_dropped = 0;
    time_t start_time = time(NULL);

    uint64_t iter = 0;
    uint64_t cumul_pkts = 0, cumul_bytes = 0, cumul_matched = 0;

    while (!g_quit) {
        sleep(cfg->interval_sec);
        if (g_quit) break;
        iter++;

        uint64_t total_pkts = 0, total_bytes = 0, total_matched = 0;
        time_t now_time = time(NULL);
        uint64_t uptime = (uint64_t)difftime(now_time, start_time);

        printf("\n========== HyperDPI Stats [%lu] ==========\n", iter);

        for (int i = 0; i < cfg->nb_workers; i++) {
            uint64_t cur_pkts = __atomic_load_n(
                &cfg->worker_cfgs[i].packets_processed, __ATOMIC_RELAXED);
            uint64_t cur_bytes = __atomic_load_n(
                &cfg->worker_cfgs[i].bytes_processed, __ATOMIC_RELAXED);
            uint64_t cur_matched = __atomic_load_n(
                &cfg->worker_cfgs[i].packets_matched, __ATOMIC_RELAXED);

            uint64_t dp = cur_pkts - prev_worker_pkts[i];
            uint64_t db = cur_bytes - prev_worker_bytes[i];
            uint64_t dm = cur_matched - prev_worker_matched[i];

            total_pkts += dp;
            total_bytes += db;
            total_matched += dm;

            double w_mbps = calc_mbps(db, cfg->interval_sec);
            uint64_t w_pps = dp / cfg->interval_sec;
            double match_pct = dp > 0 ? (double)dm / dp * 100.0 : 0.0;
            printf("Worker %d: +%lu pkts (+%lu pps), +%lu bytes (%.2f Mbps), "
                   "+%lu matched (%.1f%%), total %lu matched\n",
                   i, dp, w_pps, db, w_mbps, dm, match_pct, cur_matched);

            prev_worker_pkts[i] = cur_pkts;
            prev_worker_bytes[i] = cur_bytes;
            prev_worker_matched[i] = cur_matched;
        }

        uint64_t cur_tx_sent = __atomic_load_n(cfg->tx_sent, __ATOMIC_RELAXED);
        uint64_t cur_tx_dropped = __atomic_load_n(cfg->tx_dropped, __ATOMIC_RELAXED);
        uint64_t tx_sent = cur_tx_sent - prev_tx_sent;
        uint64_t tx_dropped = cur_tx_dropped - prev_tx_dropped;
        double tx_drop_pct = (tx_sent + tx_dropped) > 0
            ? (double)tx_dropped / (tx_sent + tx_dropped) * 100.0 : 0.0;

        printf("TX: +%lu sent, +%lu dropped (%.1f%% loss)\n",
               tx_sent, tx_dropped, tx_drop_pct);

        double total_mbps = calc_mbps(total_bytes, cfg->interval_sec);
        uint64_t total_pps = total_pkts / cfg->interval_sec;
        double match_rate = total_pkts > 0
            ? (double)total_matched / total_pkts * 100.0 : 0.0;

        cumul_pkts += total_pkts;
        cumul_bytes += total_bytes;
        cumul_matched += total_matched;

        printf("Interval: +%lu pkts (+%lu pps), %.2f Mbps, +%lu matched (%.1f%%)\n",
               total_pkts, total_pps, total_mbps, total_matched, match_rate);
        printf("Cumulative: %lu pkts, %lu bytes, %lu matched\n",
               cumul_pkts, cumul_bytes, cumul_matched);
        printf("Flow table: %u active flows\n", flow_table_count(cfg->ft));
        printf("Uptime: %lus\n", uptime);

        printf("=========================================\n");
        fflush(stdout);

        prev_tx_sent = cur_tx_sent;
        prev_tx_dropped = cur_tx_dropped;

        flow_table_cleanup(cfg->ft, cfg->flow_timeout);
    }

    return 0;
}
