#ifndef QUICP_H
#define QUICP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t quicp_status_t;
typedef struct quicp_bridge quicp_bridge_t;

typedef struct {
  const uint8_t *data;
  uint32_t len;
} quicp_input_packet_t;

typedef struct {
  uint8_t *data;
  uint32_t capacity;
  uint32_t len;
} quicp_output_packet_t;

typedef struct {
  uint32_t inputs_consumed;
  uint32_t outputs_written;
} quicp_batch_result_t;

#define QUICP_ABI_VERSION 1u
#define QUICP_MAX_BATCH_PACKETS 64u

#define QUICP_STATUS_OK 0u
#define QUICP_STATUS_WOULD_BLOCK 1u
#define QUICP_STATUS_BUFFER_TOO_SMALL 2u
#define QUICP_STATUS_INVALID_ARGUMENT 3u
#define QUICP_STATUS_NOT_READY 4u
#define QUICP_STATUS_CLOSED 5u
#define QUICP_STATUS_PANIC 6u

uint32_t quicp_abi_version(void);
quicp_status_t quicp_bridge_create(quicp_bridge_t **out_bridge);
/* Descriptor, result, bridge, input, and output ranges must not overlap. Structural pointer, count,
 * and fixed descriptor/bridge/result overlap errors leave caller-owned result and output memory
 * unchanged. Packet-buffer range and semantic errors clear result and output lengths. */
quicp_status_t quicp_bridge_process_batch(quicp_bridge_t *bridge,
                                          const quicp_input_packet_t *inputs,
                                          uint32_t input_count,
                                          quicp_output_packet_t *outputs,
                                          uint32_t output_count,
                                          quicp_batch_result_t *result);
quicp_status_t quicp_bridge_close(quicp_bridge_t **bridge);

#ifdef __cplusplus
}
#endif

#endif
