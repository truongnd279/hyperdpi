#include "worker_thread.h"
#include "app_config.h"

#include <rte_log.h>
#include <rte_pause.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <string.h>
#include <strings.h>

extern volatile int g_quit;

static const char *mem_find(const char *buf, uint32_t buf_len,
                            const char *needle, int needle_len)
{
    if (needle_len <= 0 || (uint32_t)needle_len > buf_len) return NULL;
    uint32_t end = buf_len - (uint32_t)needle_len;
    for (uint32_t i = 0; i <= end; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0)
            return buf + i;
    }
    return NULL;
}

static int extract_http_url(const char *payload, uint32_t payload_len,
                            char *out, int out_size)
{
    const char *methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH "};
    const char *path_start = NULL;

    for (int i = 0; i < 6; i++) {
        int mlen = (int)strlen(methods[i]);
        if (payload_len >= (uint32_t)mlen &&
            strncasecmp(payload, methods[i], mlen) == 0) {
            path_start = payload + mlen;
            break;
        }
    }
    if (!path_start) return 0;

    const char *http_term = mem_find(payload, payload_len, " HTTP/", 6);
    const char *path_end;
    if (http_term && http_term > path_start)
        path_end = http_term;
    else
        path_end = payload + payload_len;

    int path_len = (int)(path_end - path_start);
    if (path_len <= 0) return 0;
    if (path_len > 256) path_len = 256;

    char host[128] = {0};
    const char *host_hdr = mem_find(payload, payload_len, "Host:", 5);
    if (host_hdr) {
        host_hdr += 5;
        uint32_t remaining = (uint32_t)(payload + payload_len - host_hdr);
        while (remaining > 0 && (*host_hdr == ' ' || *host_hdr == '\t')) {
            host_hdr++;
            remaining--;
        }
        if (remaining > 0) {
            const char *host_end = mem_find(host_hdr, remaining, "\r\n", 2);
            if (!host_end) host_end = mem_find(host_hdr, remaining, "\n", 1);
            if (!host_end) host_end = host_hdr + remaining;
            int hlen = (int)(host_end - host_hdr);
            if (hlen > 0 && hlen < 126) {
                memcpy(host, host_hdr, hlen);
                host[hlen] = '\0';
            }
        }
    }

    if (host[0] == '\0') return 0;

    int n = snprintf(out, out_size, "http://%s", host);
    if (n <= 0 || n >= out_size) return 0;

    int remaining = out_size - n - 1;
    int copy_len = (path_len < remaining) ? path_len : remaining;
    memcpy(out + n, path_start, copy_len);
    out[n + copy_len] = '\0';
    return (int)strlen(out);
}

static int extract_tls_sni(const char *payload, uint32_t payload_len,
                           char *out, int out_size)
{
    if (payload_len < 5) return 0;
    if (payload[0] != 0x16) return 0;

    uint32_t offset = 5;

    if (offset + 4 > payload_len) return 0;
    if (payload[offset] != 0x01) return 0;
    offset += 4;

    if (offset + 34 > payload_len) return 0;
    offset += 34;

    if (offset + 1 > payload_len) return 0;
    uint8_t sid_len = payload[offset];
    offset += 1 + sid_len;

    if (offset + 2 > payload_len) return 0;
    uint16_t cs_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cs_len;

    if (offset + 1 > payload_len) return 0;
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    if (offset + 2 > payload_len) return 0;
    uint16_t ext_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    uint32_t ext_end = offset + ext_len;
    if (ext_end > payload_len) ext_end = payload_len;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)payload[offset] << 8) | payload[offset + 1];
        uint16_t ext_data_len = ((uint16_t)payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;
        if (offset + ext_data_len > ext_end) break;

        if (ext_type == 0x0000) {
            if (ext_data_len < 2) break;
            offset += 2;

            if (offset + 3 > ext_end) break;
            if (payload[offset] == 0x00) {
                uint16_t name_len = ((uint16_t)payload[offset + 1] << 8) | payload[offset + 2];
                offset += 3;
                if (offset + name_len <= ext_end) {
                    snprintf(out, out_size, "HOST://");
                    int prefix = (int)strlen(out);
                    int copy_len = name_len;
                    if (copy_len > out_size - prefix - 1)
                        copy_len = out_size - prefix - 1;
                    memcpy(out + prefix, payload + offset, copy_len);
                    out[prefix + copy_len] = '\0';
                    return (int)strlen(out);
                }
            }
        }
        offset += ext_data_len;
    }
    return 0;
}

int worker_thread_proc(void *arg)
{
    struct worker_thread_config *cfg = (struct worker_thread_config *)arg;

    RTE_LOG(INFO, USER1, "Worker %u started on lcore %u\n",
            cfg->worker_id, cfg->lcore_id);

    struct rte_mbuf *pkts[MAX_BURST_SIZE];
    __atomic_store_n(&cfg->packets_processed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->bytes_processed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->packets_matched, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->http_packets, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->https_packets, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->non_dpi_packets, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->packets_dropped, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&cfg->packets_forwarded, 0, __ATOMIC_RELAXED);

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
            char *p = rte_pktmbuf_mtod(mbuf, char *);

            __atomic_add_fetch(&cfg->bytes_processed, pkt_len, __ATOMIC_RELAXED);

            /* L2: Ethernet */
            if (pkt_len < sizeof(struct rte_ether_hdr)) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
            uint32_t offset = sizeof(struct rte_ether_hdr);
            uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

            while (ether_type == RTE_ETHER_TYPE_VLAN ||
                   ether_type == RTE_ETHER_TYPE_QINQ) {
                if (pkt_len < offset + sizeof(struct rte_vlan_hdr)) break;
                struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(p + offset);
                offset += sizeof(struct rte_vlan_hdr);
                ether_type = rte_be_to_cpu_16(vlan->eth_proto);
            }

            if (ether_type != RTE_ETHER_TYPE_IPV4) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            /* L3: IPv4 */
            if (pkt_len < offset + sizeof(struct rte_ipv4_hdr)) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(p + offset);
            uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) * 4;
            if (ip_hdr_len < sizeof(struct rte_ipv4_hdr) ||
                pkt_len < offset + ip_hdr_len) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            uint8_t proto = ip->next_proto_id;
            if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            offset += ip_hdr_len;

            /* L4: Transport */
            uint16_t dst_port = 0;
            uint32_t l7_offset = 0;

            if (proto == IPPROTO_TCP) {
                if (pkt_len < offset + sizeof(struct rte_tcp_hdr)) {
                    __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                    rte_pktmbuf_free(mbuf);
                    continue;
                }
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(p + offset);
                dst_port = rte_be_to_cpu_16(tcp->dst_port);
                uint32_t tcp_hdr_len = ((tcp->data_off >> 4) & 0x0f) * 4;
                if (tcp_hdr_len < sizeof(struct rte_tcp_hdr)) {
                    __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                    rte_pktmbuf_free(mbuf);
                    continue;
                }
                l7_offset = offset + tcp_hdr_len;
            } else {
                if (pkt_len < offset + sizeof(struct rte_udp_hdr)) {
                    __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                    rte_pktmbuf_free(mbuf);
                    continue;
                }
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(p + offset);
                dst_port = rte_be_to_cpu_16(udp->dst_port);
                l7_offset = offset + sizeof(struct rte_udp_hdr);
            }

            /* Port filter: only HTTP(80) or HTTPS(443) */
            if (dst_port != 80 && dst_port != 443) {
                __atomic_add_fetch(&cfg->non_dpi_packets, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            /* Flow table */
            struct flow_key key;
            flow_table_extract_key(mbuf, &key);
            flow_table_update_stats(cfg->ft, &key, pkt_len);

            /* L7: Application layer extraction */
            uint32_t payload_len = (l7_offset < pkt_len) ? pkt_len - l7_offset : 0;
            const char *app_data = (payload_len > 0) ? p + l7_offset : "";

            char scan_data[1024];
            int scan_len = 0;

            if (dst_port == 80) {
                __atomic_add_fetch(&cfg->http_packets, 1, __ATOMIC_RELAXED);
                scan_len = extract_http_url(app_data, payload_len,
                                            scan_data, (int)sizeof(scan_data));
            } else {
                __atomic_add_fetch(&cfg->https_packets, 1, __ATOMIC_RELAXED);
                scan_len = extract_tls_sni(app_data, payload_len,
                                           scan_data, (int)sizeof(scan_data));
            }

            /* Hyperscan DPI scan */
            int should_drop = 0;
            if (scan_len > 0) {
                struct hs_match_result result;
                if (hs_engine_scan(cfg->hs, scan_data, (unsigned int)scan_len,
                                   &result, cfg->scratch) == 0 && result.matched) {
                    __atomic_add_fetch(&cfg->packets_matched, 1, __ATOMIC_RELAXED);

                    uint32_t sip = rte_be_to_cpu_32(key.src_ip);
                    uint32_t dip = rte_be_to_cpu_32(key.dst_ip);
                    RTE_LOG(NOTICE, USER1,
                            "MATCH rule=%u action=%s %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu [%s]",
                            result.rule_id,
                            result.action == HS_ACTION_DROP ? "DROP" : "FORWARD",
                            (sip >> 24) & 0xff, (sip >> 16) & 0xff,
                            (sip >> 8) & 0xff, sip & 0xff,
                            rte_be_to_cpu_16(key.src_port),
                            (dip >> 24) & 0xff, (dip >> 16) & 0xff,
                            (dip >> 8) & 0xff, dip & 0xff,
                            rte_be_to_cpu_16(key.dst_port),
                            scan_data);

                    if (result.action == HS_ACTION_DROP)
                        should_drop = 1;
                }
            }

            __atomic_add_fetch(&cfg->packets_processed, 1, __ATOMIC_RELAXED);

            if (should_drop) {
                __atomic_add_fetch(&cfg->packets_dropped, 1, __ATOMIC_RELAXED);
                rte_pktmbuf_free(mbuf);
            } else {
                __atomic_add_fetch(&cfg->packets_forwarded, 1, __ATOMIC_RELAXED);
                if (rte_ring_enqueue(cfg->tx_ring, mbuf) != 0) {
                    rte_pktmbuf_free(mbuf);
                }
            }
        }
    }

    return 0;
}
