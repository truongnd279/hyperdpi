#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "app_config.h"
#include "rx_thread.h"
#include "worker_thread.h"
#include "tx_thread.h"
#include "stats_thread.h"
#include "flow_table.h"
#include "hyperscan_engine.h"

static struct app_config g_cfg;
static struct rte_mempool *g_pool = NULL;
static struct rte_ring **g_worker_rings = NULL;
static struct rte_ring *g_tx_ring = NULL;
static struct flow_table *g_ft = NULL;
static struct hs_engine *g_hs = NULL;

static struct worker_thread_config *g_worker_cfgs = NULL;
static struct tx_thread_config g_tx_cfg;
static struct stats_thread_config g_stats_cfg;

static volatile int g_quit = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_quit = 1;
    RTE_LOG(INFO, USER1, "Signal received, shutting down...\n");
}

static int port_init(uint16_t port_id, struct rte_mempool *pool)
{
    int ret;
    uint16_t nb_rxd = g_cfg.nb_rx_desc;
    uint16_t nb_txd = g_cfg.nb_tx_desc;

    struct rte_eth_dev_info dev_info;
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to get device info: %s\n",
                 rte_strerror(-ret));

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
            .split_hdr_size = 0,
        },
        .txmode = {
            .offloads = DEV_TX_OFFLOAD_MBUF_FAST_FREE,
        },
    };

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to configure port %u: %s\n",
                 port_id, rte_strerror(-ret));

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to adjust descriptors: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL, pool);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to setup RX queue: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to setup TX queue: %s\n",
                 rte_strerror(-ret));

    ret = rte_eth_dev_start(port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Failed to start port %u: %s\n",
                 port_id, rte_strerror(-ret));

    rte_eth_promiscuous_enable(port_id);
    RTE_LOG(INFO, USER1, "Port %u initialized\n", port_id);
    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    /* Default config */
    app_config_default(&g_cfg);

    /* Parse config file if provided as argument */
    /* Initialize EAL first (consumes DPDK args) */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");

    /* Config path: first non-EAL argument overrides default */
    const char *cfg_path = "config/hyperdpi.cfg";
    if (argc > ret)
        cfg_path = argv[ret];
    app_config_load(&g_cfg, cfg_path);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create memory pool */
    g_pool = rte_pktmbuf_pool_create("mbuf_pool",
                                     g_cfg.mempool_size,
                                     g_cfg.mempool_cache,
                                     0,
                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                     rte_socket_id());
    if (!g_pool)
        rte_exit(EXIT_FAILURE, "Failed to create mempool\n");

    uint16_t port_id = 0;
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No available ports\n");

    /* Match config PCI address to port */
    for (uint16_t p = 0; p < nb_ports; p++) {
        struct rte_eth_dev_info dev_info;
        if (rte_eth_dev_info_get(p, &dev_info) == 0) {
            char port_pci[NAME_SIZE];
            snprintf(port_pci, sizeof(port_pci), "%s",
                     dev_info.device->name);
            if (strstr(port_pci, g_cfg.pci_addr) ||
                strcmp(g_cfg.pci_addr, "0000:00:08.0") == 0) {
                port_id = p;
                break;
            }
        }
    }
    port_init(port_id, g_pool);

    /* Create Hyperscan engine */
    g_hs = hs_engine_create(g_cfg.rules_file, g_cfg.hs_mode);
    if (!g_hs)
        rte_exit(EXIT_FAILURE, "Failed to create Hyperscan engine\n");

    /* Create flow table */
    g_ft = flow_table_create(g_cfg.max_flows);
    if (!g_ft)
        rte_exit(EXIT_FAILURE, "Failed to create flow table\n");

    /* Create rings */
    g_worker_rings = rte_zmalloc("worker_rings",
        g_cfg.nb_workers * sizeof(struct rte_ring *), 0);

    char ring_name[64];
    for (int i = 0; i < g_cfg.nb_workers; i++) {
        snprintf(ring_name, sizeof(ring_name), "rx_worker_ring_%d", i);
        g_worker_rings[i] = rte_ring_create(ring_name,
                                            g_cfg.rx_worker_ring_size,
                                            rte_socket_id(),
                                            RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!g_worker_rings[i])
            rte_exit(EXIT_FAILURE, "Failed to create ring %d\n", i);
    }

    g_tx_ring = rte_ring_create("tx_ring",
                                g_cfg.tx_ring_size,
                                rte_socket_id(),
                                RING_F_SC_DEQ);
    if (!g_tx_ring)
        rte_exit(EXIT_FAILURE, "Failed to create TX ring\n");

    /* Prepare worker configs */
    g_worker_cfgs = rte_zmalloc("worker_cfgs",
        g_cfg.nb_workers * sizeof(struct worker_thread_config), 0);

    for (int i = 0; i < g_cfg.nb_workers; i++) {
        g_worker_cfgs[i].worker_id = i;
        g_worker_cfgs[i].lcore_id = g_cfg.worker_lcores[i];
        g_worker_cfgs[i].rx_ring = g_worker_rings[i];
        g_worker_cfgs[i].tx_ring = g_tx_ring;
        g_worker_cfgs[i].pool = g_pool;
        g_worker_cfgs[i].ft = g_ft;
        g_worker_cfgs[i].hs = g_hs;
        g_worker_cfgs[i].scratch = hs_engine_alloc_scratch(g_hs);
        if (!g_worker_cfgs[i].scratch)
            rte_exit(EXIT_FAILURE, "Failed to allocate scratch for worker %d\n", i);
    }

    /* Prepare TX config */
    g_tx_cfg.port_id = port_id;
    g_tx_cfg.lcore_id = g_cfg.tx_lcore;
    g_tx_cfg.tx_ring = g_tx_ring;
    g_tx_cfg.burst_size = g_cfg.burst_size;

    /* Prepare Stats config */
    g_stats_cfg.lcore_id = g_cfg.stats_lcore;
    g_stats_cfg.ft = g_ft;
    g_stats_cfg.worker_cfgs = g_worker_cfgs;
    g_stats_cfg.nb_workers = g_cfg.nb_workers;
    g_stats_cfg.tx_sent = &g_tx_cfg.packets_sent;
    g_stats_cfg.tx_dropped = &g_tx_cfg.packets_dropped;
    g_stats_cfg.interval_sec = g_cfg.stats_interval;
    g_stats_cfg.flow_timeout = g_cfg.flow_timeout;

    /* Prepare RX config */
    struct rx_thread_config rx_cfg = {
        .port_id = port_id,
        .lcore_id = g_cfg.rx_lcore,
        .worker_rings = g_worker_rings,
        .nb_workers = g_cfg.nb_workers,
        .pool = g_pool,
        .burst_size = g_cfg.burst_size,
    };

    /* Launch threads on dedicated lcores */
    RTE_LOG(INFO, USER1, "Launching RX on lcore %u\n", rx_cfg.lcore_id);
    rte_eal_remote_launch(rx_thread_proc, &rx_cfg, rx_cfg.lcore_id);

    for (int i = 0; i < g_cfg.nb_workers; i++) {
        RTE_LOG(INFO, USER1, "Launching Worker %d on lcore %u\n",
                i, g_worker_cfgs[i].lcore_id);
        rte_eal_remote_launch(worker_thread_proc, &g_worker_cfgs[i],
                              g_worker_cfgs[i].lcore_id);
    }

    RTE_LOG(INFO, USER1, "Launching TX on lcore %u\n", g_tx_cfg.lcore_id);
    rte_eal_remote_launch(tx_thread_proc, &g_tx_cfg, g_tx_cfg.lcore_id);

    RTE_LOG(INFO, USER1, "Launching Stats on lcore %u\n",
            g_stats_cfg.lcore_id);
    rte_eal_remote_launch(stats_thread_proc, &g_stats_cfg,
                          g_stats_cfg.lcore_id);

    /* Wait for all threads */
    rte_eal_mp_wait_lcore();

    /* Cleanup */
    RTE_LOG(INFO, USER1, "Cleaning up...\n");
    for (int i = 0; i < g_cfg.nb_workers; i++) {
        if (g_worker_cfgs[i].scratch)
            hs_free_scratch(g_worker_cfgs[i].scratch);
    }
    hs_engine_destroy(g_hs);
    flow_table_destroy(g_ft);
    for (int i = 0; i < g_cfg.nb_workers; i++)
        rte_ring_free(g_worker_rings[i]);
    rte_ring_free(g_tx_ring);
    rte_free(g_worker_cfgs);
    rte_free(g_worker_rings);
    rte_mempool_free(g_pool);

    RTE_LOG(INFO, USER1, "HyperDPI shutdown complete\n");
    return 0;
}
