#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

typedef uint8_t portid_t;

int
stats_mapping_setup(portid_t port_id);

void
nic_stats_display(portid_t port_id);

void
nic_stats_clear(portid_t port_id);

void
nic_xstats_display(portid_t port_id);

void
nic_xstats_clear(portid_t port_id);

void
fdir_get_infos(portid_t port_id);
