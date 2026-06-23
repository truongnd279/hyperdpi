#include "app_config.h"

#include <hs/hs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void app_config_default(struct app_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->pci_addr, sizeof(cfg->pci_addr), "0000:00:08.0");
    cfg->nb_rx_desc = 2048;
    cfg->nb_tx_desc = 2048;
    cfg->mempool_size = 65535;
    cfg->mempool_cache = 256;
    cfg->burst_size = 64;

    cfg->rx_lcore = 1;
    cfg->tx_lcore = 2;
    cfg->worker_lcores[0] = 3;
    cfg->worker_lcores[1] = 4;
    cfg->worker_lcores[2] = 5;
    cfg->worker_lcores[3] = 6;
    cfg->nb_workers = 4;
    cfg->stats_lcore = 7;

    cfg->rx_worker_ring_size = 131072;
    cfg->tx_ring_size = 131072;

    cfg->max_flows = 1048576;
    cfg->flow_timeout = 60;

    snprintf(cfg->rules_file, sizeof(cfg->rules_file), "rules/dpi_rules.txt");
    cfg->hs_mode = HS_MODE_BLOCK;
    cfg->stats_interval = 5;
}

static int parse_line(struct app_config *cfg, const char *line)
{
    char key[128], val[512];
    if (sscanf(line, "%127[^=] = %511[^\r\n]", key, val) < 2)
        return -1;

    if (strcmp(key, "pci_addr") == 0)
        snprintf(cfg->pci_addr, sizeof(cfg->pci_addr), "%.63s", val);
    else if (strcmp(key, "nb_rx_desc") == 0)
        cfg->nb_rx_desc = atoi(val);
    else if (strcmp(key, "nb_tx_desc") == 0)
        cfg->nb_tx_desc = atoi(val);
    else if (strcmp(key, "mempool_size") == 0)
        cfg->mempool_size = atoi(val);
    else if (strcmp(key, "mempool_cache") == 0)
        cfg->mempool_cache = atoi(val);
    else if (strcmp(key, "burst_size") == 0)
        cfg->burst_size = atoi(val);
    else if (strcmp(key, "rx_lcore") == 0)
        cfg->rx_lcore = atoi(val);
    else if (strcmp(key, "tx_lcore") == 0)
        cfg->tx_lcore = atoi(val);
    else if (strcmp(key, "worker_lcores") == 0) {
        char *p = val, *tok;
        cfg->nb_workers = 0;
        while ((tok = strtok(p, ",")) != NULL) {
            if (cfg->nb_workers >= MAX_WORKERS) break;
            cfg->worker_lcores[cfg->nb_workers++] = atoi(tok);
            p = NULL;
        }
    } else if (strcmp(key, "stats_lcore") == 0)
        cfg->stats_lcore = atoi(val);
    else if (strcmp(key, "nb_workers") == 0)
        cfg->nb_workers = atoi(val);
    else if (strcmp(key, "rx_worker_ring_size") == 0)
        cfg->rx_worker_ring_size = atoi(val);
    else if (strcmp(key, "tx_ring_size") == 0)
        cfg->tx_ring_size = atoi(val);
    else if (strcmp(key, "max_flows") == 0)
        cfg->max_flows = atoi(val);
    else if (strcmp(key, "flow_timeout") == 0)
        cfg->flow_timeout = atoi(val);
    else if (strcmp(key, "rules_file") == 0)
        snprintf(cfg->rules_file, sizeof(cfg->rules_file), "%s", val);
    else if (strcmp(key, "mode") == 0) {
        if (strstr(val, "STREAM"))
            cfg->hs_mode = HS_MODE_STREAM;
        else
            cfg->hs_mode = HS_MODE_BLOCK;
    } else if (strcmp(key, "interval") == 0)
        cfg->stats_interval = atoi(val);
    return 0;
}

int app_config_load(struct app_config *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config: %s\n", path);
        return -1;
    }

    app_config_default(cfg);

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '[')
            continue;
        parse_line(cfg, p);
    }
    fclose(fp);
    return 0;
}
