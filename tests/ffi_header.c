#include <stddef.h>
#include "quicp.h"

/* Mirror the Rust const assertions in src/ffi.rs. No runtime is required. */
#ifdef __cplusplus
#define ABI_ASSERT(condition) static_assert(condition, #condition)
#define ABI_ALIGN(type) alignof(type)
#else
#define ABI_ASSERT(condition) _Static_assert(condition, #condition)
#define ABI_ALIGN(type) _Alignof(type)
#endif
#define ABI_OFFSET(type, field, expected) \
  ABI_ASSERT(offsetof(type, field) == (expected))

ABI_ASSERT(sizeof(quicp_status_t) == 4);
ABI_ASSERT(sizeof(quicp_flow_t) == 8);
ABI_ASSERT(sizeof(quicp_socket_address_t) == 24);
ABI_ASSERT(ABI_ALIGN(quicp_socket_address_t) == 4);
ABI_OFFSET(quicp_socket_address_t, family, 0);
ABI_OFFSET(quicp_socket_address_t, port, 4);
ABI_OFFSET(quicp_socket_address_t, reserved, 6);
ABI_OFFSET(quicp_socket_address_t, address, 8);
ABI_ASSERT(sizeof(quicp_path_config_t) == 48);
ABI_ASSERT(ABI_ALIGN(quicp_path_config_t) == 4);
ABI_OFFSET(quicp_path_config_t, local, 0);
ABI_OFFSET(quicp_path_config_t, peer, 24);
ABI_ASSERT(sizeof(quicp_engine_config_t) == 120);
ABI_ASSERT(ABI_ALIGN(quicp_engine_config_t) == 4);
ABI_OFFSET(quicp_engine_config_t, abi_version, 0);
ABI_OFFSET(quicp_engine_config_t, role, 4);
ABI_OFFSET(quicp_engine_config_t, path_count, 8);
ABI_OFFSET(quicp_engine_config_t, paths, 12);
ABI_OFFSET(quicp_engine_config_t, packet_capacity, 108);
ABI_OFFSET(quicp_engine_config_t, mtu, 112);
ABI_OFFSET(quicp_engine_config_t, recovery_mode, 116);
ABI_OFFSET(quicp_bytes_t, data, 0);
ABI_OFFSET(quicp_bytes_t, length, sizeof(void *));
ABI_ASSERT(ABI_ALIGN(quicp_bytes_t) == ABI_ALIGN(void *));
#if UINTPTR_MAX == UINT64_MAX
ABI_ASSERT(sizeof(quicp_bytes_t) == 16);
#elif UINTPTR_MAX == UINT32_MAX
ABI_ASSERT(sizeof(quicp_bytes_t) == 8);
#endif
ABI_ASSERT(sizeof(quicp_tls_config_t) == 4 * sizeof(quicp_bytes_t));
ABI_ASSERT(ABI_ALIGN(quicp_tls_config_t) == ABI_ALIGN(quicp_bytes_t));
ABI_OFFSET(quicp_tls_config_t, server_name, 0);
ABI_OFFSET(quicp_tls_config_t, ca_certificate, sizeof(quicp_bytes_t));
ABI_OFFSET(quicp_tls_config_t, certificate, 2 * sizeof(quicp_bytes_t));
ABI_OFFSET(quicp_tls_config_t, private_key, 3 * sizeof(quicp_bytes_t));
ABI_ASSERT(sizeof(quicp_recovery_snapshot_t) == 104);
ABI_ASSERT(ABI_ALIGN(quicp_recovery_snapshot_t) == ABI_ALIGN(uint64_t));
ABI_OFFSET(quicp_recovery_snapshot_t, source_sent, 0);
ABI_OFFSET(quicp_recovery_snapshot_t, source_received, 8);
ABI_OFFSET(quicp_recovery_snapshot_t, repair_sent, 16);
ABI_OFFSET(quicp_recovery_snapshot_t, recovered, 24);
ABI_OFFSET(quicp_recovery_snapshot_t, replayed, 32);
ABI_OFFSET(quicp_recovery_snapshot_t, fallback, 40);
ABI_OFFSET(quicp_recovery_snapshot_t, dropped, 48);
ABI_OFFSET(quicp_recovery_snapshot_t, early_accepted, 56);
ABI_OFFSET(quicp_recovery_snapshot_t, early_rejected, 64);
ABI_OFFSET(quicp_recovery_snapshot_t, path_lost_packets, 72);
ABI_OFFSET(quicp_recovery_snapshot_t, max_path_rtt_micros, 80);
ABI_OFFSET(quicp_recovery_snapshot_t, queued_datagrams, 88);
ABI_OFFSET(quicp_recovery_snapshot_t, retained_source_bytes, 96);
