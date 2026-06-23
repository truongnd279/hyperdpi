cmake_minimum_required(VERSION 3.16)
project(hyperdpi C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- DPDK ----------
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# ---------- Hyperscan ----------
find_library(HS_LIBRARY hs REQUIRED)
find_path(HS_INCLUDE_DIR hs/hs.h REQUIRED)

# ---------- Sources ----------
set(SOURCES
    src/main.c
    src/rx_thread.c
    src/worker_thread.c
    src/tx_thread.c
    src/stats_thread.c
    src/flow_table.c
    src/hyperscan_engine.c
    src/app_config.c
)

set(HYPERDPI_CFLAGS
    -O3
    -march=native
    -DALLOW_EXPERIMENTAL_API
)

add_executable(hyperdpi ${SOURCES})

target_include_directories(hyperdpi PRIVATE
    ${DPDK_INCLUDE_DIRS}
    ${HS_INCLUDE_DIR}
    src
)

target_compile_options(hyperdpi PRIVATE ${HYPERDPI_CFLAGS})

target_link_libraries(hyperdpi PRIVATE
    ${DPDK_LIBRARIES}
    ${HS_LIBRARY}
    pthread
    m
    numa
)

target_link_directories(hyperdpi PRIVATE
    ${DPDK_LIBRARY_DIRS}
)

# ---------- Install ----------
install(TARGETS hyperdpi RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION etc/hyperdpi)
install(DIRECTORY rules/ DESTINATION etc/hyperdpi/rules)
