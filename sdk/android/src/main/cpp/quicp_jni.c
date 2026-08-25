#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "quicp.h"

#define INPUT_FIELDS 2
#define OUTPUT_FIELDS 3

static uint64_t pack_result(quicp_status_t status,
                            const quicp_batch_result_t *result) {
  return (uint64_t)status | ((uint64_t)result->inputs_consumed << 8) |
         ((uint64_t)result->outputs_written << 16);
}

static uint32_t read_u32(const uint8_t *bytes, uint64_t index) {
  uint32_t value;
  memcpy(&value, bytes + index * sizeof(value), sizeof(value));
  return value;
}

static void write_u32(uint8_t *bytes, uint64_t index, uint32_t value) {
  memcpy(bytes + index * sizeof(value), &value, sizeof(value));
}

static int direct_buffer(JNIEnv *env, jobject buffer, uint8_t **data,
                         uint64_t *capacity) {
  if (buffer == NULL) {
    *data = NULL;
    *capacity = 0;
    return 1;
  }
  void *address = (*env)->GetDirectBufferAddress(env, buffer);
  jlong length = (*env)->GetDirectBufferCapacity(env, buffer);
  if (address == NULL || length < 0) {
    return 0;
  }
  *data = address;
  *capacity = (uint64_t)length;
  return 1;
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpBridge_nativeCreate(JNIEnv *env,
                                                               jclass type) {
  (void)env;
  (void)type;
  quicp_bridge_t *bridge = NULL;
  return quicp_abi_version() == QUICP_ABI_VERSION &&
                 quicp_bridge_create(&bridge) == QUICP_STATUS_OK
             ? (jlong)(uintptr_t)bridge
             : 0;
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpBridge_nativeProcessBatch(
    JNIEnv *env, jclass type, jlong handle, jobject input_data,
    jobject input_descriptors, jint input_count, jobject output_data,
    jobject output_descriptors, jint output_count) {
  (void)type;
  quicp_batch_result_t result = {0};
  quicp_input_packet_t inputs[QUICP_MAX_BATCH_PACKETS];
  quicp_output_packet_t outputs[QUICP_MAX_BATCH_PACKETS];
  uint8_t *input_bytes = NULL;
  uint8_t *output_bytes = NULL;
  uint8_t *input_meta_bytes = NULL;
  uint8_t *output_meta_bytes = NULL;
  uint64_t input_capacity = 0;
  uint64_t output_capacity = 0;
  uint64_t input_meta_capacity = 0;
  uint64_t output_meta_capacity = 0;

  if (handle == 0 || input_count < 0 || output_count < 0 ||
      (uint32_t)input_count > QUICP_MAX_BATCH_PACKETS ||
      (uint32_t)output_count > QUICP_MAX_BATCH_PACKETS ||
      !direct_buffer(env, input_data, &input_bytes, &input_capacity) ||
      !direct_buffer(env, output_data, &output_bytes, &output_capacity) ||
      !direct_buffer(env, input_descriptors, &input_meta_bytes,
                     &input_meta_capacity) ||
      !direct_buffer(env, output_descriptors, &output_meta_bytes,
                     &output_meta_capacity) ||
      input_meta_capacity <
          (uint64_t)input_count * INPUT_FIELDS * sizeof(uint32_t) ||
      output_meta_capacity <
          (uint64_t)output_count * OUTPUT_FIELDS * sizeof(uint32_t)) {
    return (jlong)QUICP_STATUS_INVALID_ARGUMENT;
  }

  for (jint index = 0; index < input_count; ++index) {
    uint64_t field = (uint64_t)(uint32_t)index * INPUT_FIELDS;
    uint32_t offset = read_u32(input_meta_bytes, field);
    uint32_t length = read_u32(input_meta_bytes, field + 1);
    if ((uint64_t)offset + length > input_capacity) {
      return (jlong)QUICP_STATUS_INVALID_ARGUMENT;
    }
    inputs[index].data = input_bytes == NULL ? NULL : input_bytes + offset;
    inputs[index].len = length;
  }
  for (jint index = 0; index < output_count; ++index) {
    uint64_t field = (uint64_t)(uint32_t)index * OUTPUT_FIELDS;
    uint32_t offset = read_u32(output_meta_bytes, field);
    uint32_t capacity = read_u32(output_meta_bytes, field + 1);
    if ((uint64_t)offset + capacity > output_capacity) {
      return (jlong)QUICP_STATUS_INVALID_ARGUMENT;
    }
    outputs[index].data = output_bytes == NULL ? NULL : output_bytes + offset;
    outputs[index].capacity = capacity;
    outputs[index].len = 0;
  }

  quicp_status_t status = quicp_bridge_process_batch(
      (quicp_bridge_t *)(uintptr_t)handle, inputs, (uint32_t)input_count,
      outputs, (uint32_t)output_count, &result);
  for (jint index = 0; index < output_count; ++index) {
    uint64_t field = (uint64_t)(uint32_t)index * OUTPUT_FIELDS;
    write_u32(output_meta_bytes, field + 2, outputs[index].len);
  }
  return (jlong)pack_result(status, &result);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpBridge_nativeClose(JNIEnv *env,
                                                             jclass type,
                                                             jlong handle) {
  (void)env;
  (void)type;
  quicp_bridge_t *bridge = (quicp_bridge_t *)(uintptr_t)handle;
  return (jint)quicp_bridge_close(&bridge);
}
