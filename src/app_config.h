#ifndef HYPERDPI_APP_CONFIG_H
#define HYPERDPI_APP_CONFIG_H

#include <stdint.h>

#define MAX_WORKERS           64
#define MAX_LCORE_STR         256
#define MAX_RULES_PATH        512
#define NAME_SIZE             64
#define MAX_BURST_SIZE        64

struct app_config {
    /* DPDK */
    char pci_addr[NAME_SIZE];
    uint16_t nb_rx_desc;
    uint16_t nb_tx_desc;
    uint32_t mempool_size;
    uint32_t mempool_cache;
    uint16_t burst_size;

    /* Lcore mapping */
    unsigned rx_lcore;
    unsigned tx_lcore;
    unsigned worker_lcores[MAX_WORKERS];
    int nb_workers;
    unsigned stats_lcore;

    /* Rings */
    uint32_t rx_worker_ring_size;
    uint32_t tx_ring_size;

    /* Flow table */
    uint32_t max_flows;
    uint32_t flow_timeout;

    /* Hyperscan */
    char rules_file[MAX_RULES_PATH];
    unsigned int hs_mode;

    /* Stats */
    uint32_t stats_interval;
};

int app_config_load(struct app_config *cfg, const char *path);
void app_config_default(struct app_config *cfg);

#endif /* HYPERDPI_APP_CONFIG_H */
