# HyperDPI

High-performance Deep Packet Inspection engine built on **DPDK** and **Hyperscan**.

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────┐
 │  NIC                                                             │
 │    │ rte_eth_rx_burst()                                          │
 │    ▼                                                             │
 │  ┌──────────────────────────────────────┐                        │
 │  │  RX Thread  (1 lcore)               │                        │
 │  │  • Burst receive from NIC           │                        │
 │  │  • Extract 5-tuple flow key         │                        │
 │  │  • Hash → distribute to workers     │                        │
 │  └────────┬─────────┬─────────┬────────┘                        │
 │           │         │         │                                  │
 │      rte_ring[0]    │    rte_ring[N-1]                          │
 │           │         │         │                                  │
 │           ▼         ▼         ▼                                  │
 │  ┌──────────────────────────────────────┐                        │
 │  │  Worker Threads  (N lcores)          │                        │
 │  │  • Dequeue from per-worker ring      │                        │
 │  │  • Flow table lookup / update        │                        │
 │  │  • Hyperscan pattern matching        │                        │
 │  │  • Classify application protocol     │                        │
 │  │  • Enqueue to TX ring                │                        │
 │  └────────┬─────────┬─────────┬────────┘                        │
 │           └─────────┬───────────────────┘                        │
 │                     │ rte_ring (shared TX)                       │
 │                     ▼                                             │
 │  ┌──────────────────────────────────────┐                        │
 │  │  TX Thread  (1 lcore)                │                        │
 │  │  • Dequeue from TX ring              │                        │
 │  │  • Burst transmit to NIC             │                        │
 │  │  • Free dropped packets              │                        │
 │  └──────────────────────────────────────┘                        │
 │                                                                    │
 │  ┌──────────────────────────────────────┐                        │
 │  │  Stats Thread  (1 lcore)             │                        │
 │  │  • Periodic delta stats              │                        │
 │  │  • Throughput calculation (Mbps)     │                        │
 │  │  • Flow table idle timeout cleanup   │                        │
 │  └──────────────────────────────────────┘                        │
 └──────────────────────────────────────────────────────────────────┘
```

### Thread Model

| Thread | Lcore | Role |
|--------|-------|------|
| RX | 1 | Nhận packet từ NIC, hash 5-tuple, phân phối worker |
| Worker | 3-6 | DPI processing với Hyperscan |
| TX | 2 | Gửi packet ra NIC |
| Stats | 7 | Thống kê định kỳ + cleanup flow table |

## Requirements

- **DPDK** >= 20.11
- **Hyperscan** >= 5.4
- **Linux** (x86_64, NUMA)
- **CMake** >= 3.16

## Build

```bash
# Set up DPDK environment
export PKG_CONFIG_PATH=/path/to/dpdk/lib/x86_64-linux-gnu/pkgconfig

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Install (optional)
sudo make install
```

## Configuration

Edit `config/hyperdpi.cfg`:

```ini
[dpdk]
pci_addr = 0000:00:08.0
nb_rx_desc = 2048
nb_tx_desc = 2048
burst_size = 64

[lcores]
rx_lcore = 1
tx_lcore = 2
worker_lcores = 3,4,5,6
stats_lcore = 7

[flow_table]
max_flows = 1048576
flow_timeout = 60

[stats]
interval = 5
```

## Rules

Pattern rules in `rules/dpi_rules.txt` (CSV format):

```
id,pattern,protocol,description
1000,/http/,tcp,HTTP traffic
1001,/https/,tcp,HTTPS traffic
```

- Pattern được bao trong `//`, nội dung bên trong là Hyperscan regex
- Hỗ trợ `HS_MODE_BLOCK` (mặc định) và `HS_MODE_STREAM`

## Usage

```bash
# Bind NIC to DPDK driver
dpdk-devbind.py -b vfio-pci 0000:00:08.0

# Run with default config
sudo ./build/hyperdpi

# Run with custom config
sudo ./build/hyperdpi /path/to/hyperdpi.cfg

# EAL options
sudo ./build/hyperdpi -l 0-7 -n 4 --file-prefix=hdpi
```

## Performance

- RX/Worker/TX pipeline sử dụng lock-free `rte_ring`
- Worker scale horizontally với số lcore
- Hyperscan sử dụng compiled database + scratch space cho multi-pattern matching
- Flow table dùng `rte_hash` (cuckoo hash) cho O(1) lookup

## Project Structure

```
hyperdpi/
├── CMakeLists.txt              # Build system
├── config/
│   └── hyperdpi.cfg            # Configuration file
├── rules/
│   └── dpi_rules.txt           # DPI pattern rules
└── src/
    ├── main.c                  # Entry point, initialization
    ├── app_config.c/.h         # Config parser
    ├── rx_thread.c/.h          # Receive thread
    ├── worker_thread.c/.h      # DPI worker thread
    ├── tx_thread.c/.h          # Transmit thread
    ├── stats_thread.c/.h       # Statistics thread
    ├── flow_table.c/.h         # 5-tuple flow hash table
    └── hyperscan_engine.c/.h   # Hyperscan wrapper
```

## License

MIT
