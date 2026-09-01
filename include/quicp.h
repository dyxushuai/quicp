#ifndef QUICP_H
#define QUICP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t quicp_status_t;
typedef uint64_t quicp_flow_t;
typedef struct quicp_engine quicp_engine_t;

typedef struct {
  uint32_t family;
  uint16_t port;
  uint16_t reserved;
  uint8_t address[16];
} quicp_socket_address_t;

typedef struct {
  quicp_socket_address_t local;
  quicp_socket_address_t peer;
} quicp_path_config_t;

typedef struct {
  uint32_t abi_version;
  uint32_t role;
  uint32_t path_count;
  quicp_path_config_t paths[2];
  uint32_t packet_capacity;
  uint32_t mtu;
  uint32_t recovery_mode;
} quicp_engine_config_t;

typedef struct {
  const uint8_t *data;
  uint32_t length;
} quicp_bytes_t;

typedef struct {
  quicp_bytes_t server_name;
  quicp_bytes_t ca_certificate;
  quicp_bytes_t certificate;
  quicp_bytes_t private_key;
} quicp_tls_config_t;

typedef struct {
  uint64_t source_sent;
  uint64_t source_received;
  uint64_t repair_sent;
  uint64_t recovered;
  uint64_t replayed;
  uint64_t fallback;
  uint64_t dropped;
  uint64_t early_accepted;
  uint64_t early_rejected;
  uint64_t path_lost_packets;
  uint64_t max_path_rtt_micros;
  uint64_t queued_datagrams;
  uint64_t retained_source_bytes;
} quicp_recovery_snapshot_t;

#define QUICP_ABI_VERSION 3u
#define QUICP_MAX_PACKET_CAPACITY 4096u
#define QUICP_MAX_HOST_BYTES 253u
#define QUICP_MAX_EARLY_INITIAL_BYTES 32768u
#define QUICP_MAX_ENGINE_QUEUE_BYTES (64u * 1024u * 1024u)

#define QUICP_ROLE_CLIENT 1u
#define QUICP_ROLE_SERVER 2u
#define QUICP_RECOVERY_ADAPTIVE 1u
#define QUICP_RECOVERY_RELIABLE_ONLY 2u

#define QUICP_STATUS_OK 0u
#define QUICP_STATUS_WOULD_BLOCK 1u
#define QUICP_STATUS_BUFFER_TOO_SMALL 2u
#define QUICP_STATUS_INVALID_ARGUMENT 3u
#define QUICP_STATUS_NOT_READY 4u
#define QUICP_STATUS_CLOSED 5u
#define QUICP_STATUS_PANIC 6u
#define QUICP_STATUS_FAILED 7u

uint32_t quicp_abi_version(void);

/* abi_version must equal QUICP_ABI_VERSION. Engines are single-owner.
 * Overlapping drive calls return QUICP_STATUS_INVALID_ARGUMENT; all other
 * calls on one engine must be serialized.
 * MTU must be 1200..65527. Aggregate path queue storage must not exceed
 * QUICP_MAX_ENGINE_QUEUE_BYTES. */
quicp_status_t quicp_engine_create(const quicp_engine_config_t *config,
                                   quicp_engine_t **out_engine);
/* With tls-rustls, TLS strings are UTF-8 and copied during the call. For a
 * server, server_name must be empty and ca_certificate authenticates clients.
 * An archive built without tls-rustls returns QUICP_STATUS_INVALID_ARGUMENT
 * without copying strings or creating an engine. */
quicp_status_t quicp_engine_create_tls(const quicp_engine_config_t *config,
                                       const quicp_tls_config_t *tls,
                                       quicp_engine_t **out_engine);
quicp_status_t quicp_engine_drive(quicp_engine_t *engine,
                                  uint64_t elapsed_nanos,
                                  uint32_t max_tasks,
                                  uint32_t *processed);
quicp_status_t quicp_engine_next_timer(quicp_engine_t *engine,
                                       uint32_t *present,
                                       uint64_t *elapsed_nanos);
quicp_status_t quicp_engine_connection_state(quicp_engine_t *engine);
quicp_status_t quicp_engine_recovery_snapshot(
    quicp_engine_t *engine, quicp_recovery_snapshot_t *snapshot);

/* Underlay buffers are borrowed for the call and never retained. */
quicp_status_t quicp_engine_ingress(quicp_engine_t *engine,
                                    uint32_t path,
                                    const uint8_t *data,
                                    uint32_t length);
quicp_status_t quicp_engine_egress(quicp_engine_t *engine,
                                   uint32_t path,
                                   uint8_t *output,
                                   uint32_t capacity,
                                   uint32_t *length);
quicp_status_t quicp_engine_path_unavailable(quicp_engine_t *engine,
                                             uint32_t path);

/* Repeat the same open call after WOULD_BLOCK until it returns a flow handle. */
quicp_status_t quicp_engine_open_flow(quicp_engine_t *engine,
                                      const uint8_t *host,
                                      uint32_t host_length,
                                      uint16_t port,
                                      quicp_flow_t *flow);
/* Replay-safe opens run on an established connection; all input buffers are
 * copied before return. Initial data is limited to 32768 bytes. */
quicp_status_t quicp_engine_open_replay_safe_flow(
    quicp_engine_t *engine,
    const uint8_t *token,
    uint32_t token_length,
    uint64_t nonce,
    const uint8_t *host,
    uint32_t host_length,
    uint16_t port,
    const uint8_t *initial,
    uint32_t initial_length,
    quicp_flow_t *flow);
/* Polling an incoming OPEN never accepts it. On OK, inspect host, port, and
 * initial bytes, then pass request to accept_pending_flow or
 * reject_pending_flow. Zero-capacity buffers query the required lengths. */
quicp_status_t quicp_engine_poll_flow_request(
    quicp_engine_t *engine,
    uint64_t *request,
    uint8_t *host,
    uint32_t host_capacity,
    uint32_t *host_length,
    uint16_t *port,
    uint8_t *initial,
    uint32_t initial_capacity,
    uint32_t *initial_length);
quicp_status_t quicp_engine_poll_replay_safe_flow_request(
    quicp_engine_t *engine,
    uint64_t *request,
    uint8_t *host,
    uint32_t host_capacity,
    uint32_t *host_length,
    uint16_t *port,
    uint8_t *initial,
    uint32_t initial_capacity,
    uint32_t *initial_length);
quicp_status_t quicp_engine_accept_pending_flow(quicp_engine_t *engine,
                                                uint64_t request,
                                                quicp_flow_t *flow);
quicp_status_t quicp_engine_reject_pending_flow(quicp_engine_t *engine,
                                                uint64_t request);
/* Server-only replay policy. Secret bytes are copied, max_attempts must be in
 * 1..=65536, and the policy can be installed once per engine. */
quicp_status_t quicp_engine_configure_replay_admission(
    quicp_engine_t *engine,
    const uint8_t *secret,
    uint32_t secret_length,
    uint64_t epoch,
    uint32_t max_attempts);
/* A zero-capacity output query returns BUFFER_TOO_SMALL and writes the exact
 * required token length. */
quicp_status_t quicp_engine_issue_replay_token(quicp_engine_t *engine,
                                               uint64_t now_seconds,
                                               uint64_t ttl_seconds,
                                               uint8_t *output,
                                               uint32_t capacity,
                                               uint32_t *length);

quicp_status_t quicp_flow_read(quicp_engine_t *engine,
                               quicp_flow_t flow,
                               uint8_t *output,
                               uint32_t capacity,
                               uint32_t *read);
quicp_status_t quicp_flow_write(quicp_engine_t *engine,
                                quicp_flow_t flow,
                                const uint8_t *input,
                                uint32_t length,
                                uint32_t *written);
quicp_status_t quicp_flow_flush(quicp_engine_t *engine, quicp_flow_t flow);
quicp_status_t quicp_flow_shutdown(quicp_engine_t *engine,
                                   quicp_flow_t flow);
/* Abortively resets the flow with QUICP_FLOW_ABORT and releases its handle. */
quicp_status_t quicp_flow_close(quicp_engine_t *engine, quicp_flow_t flow);
quicp_status_t quicp_engine_close(quicp_engine_t **engine);

#ifdef __cplusplus
}
#endif

#endif
