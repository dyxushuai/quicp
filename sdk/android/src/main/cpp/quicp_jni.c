#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "quicp.h"

static int direct_buffer(JNIEnv *env, jobject buffer, uint8_t **data,
                         uint64_t *capacity) {
  if (buffer == NULL) return 0;
  void *address = (*env)->GetDirectBufferAddress(env, buffer);
  jlong length = (*env)->GetDirectBufferCapacity(env, buffer);
  if (address == NULL || length < 0) return 0;
  *data = address;
  *capacity = (uint64_t)length;
  return 1;
}

static jlong pack(quicp_status_t status, uint32_t value) {
  return (jlong)((uint64_t)status | ((uint64_t)value << 32));
}

static int borrow_bytes(JNIEnv *env, jbyteArray input, int allow_empty,
                        jbyte **elements, quicp_bytes_t *output) {
  if (input == NULL) return 0;
  jsize length = (*env)->GetArrayLength(env, input);
  if (length < 0 || (length == 0 && !allow_empty)) return 0;
  if (length == 0) {
    *elements = NULL;
    output->data = NULL;
    output->length = 0;
    return 1;
  }
  *elements = (*env)->GetByteArrayElements(env, input, NULL);
  if (*elements == NULL) return 0;
  output->data = (const uint8_t *)*elements;
  output->length = (uint32_t)length;
  return 1;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeConfigSize(
    JNIEnv *env, jclass type) {
  (void)env;
  (void)type;
  return (jint)sizeof(quicp_engine_config_t);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeInitConfig(
    JNIEnv *env, jclass type, jobject config_buffer, jint role,
    jint path_count, jint packet_capacity, jint mtu, jint recovery_mode) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (!direct_buffer(env, config_buffer, &bytes, &capacity) ||
      capacity < sizeof(quicp_engine_config_t) || path_count < 1 ||
      path_count > 2 || packet_capacity <= 0 || mtu <= 0) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  quicp_engine_config_t config;
  memset(&config, 0, sizeof(config));
  config.abi_version = QUICP_ABI_VERSION;
  config.role = (uint32_t)role;
  config.path_count = (uint32_t)path_count;
  config.packet_capacity = (uint32_t)packet_capacity;
  config.mtu = (uint32_t)mtu;
  config.recovery_mode = (uint32_t)recovery_mode;
  memcpy(bytes, &config, sizeof(config));
  return QUICP_STATUS_OK;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeSetPath(
    JNIEnv *env, jclass type, jobject config_buffer, jint path,
    jbyteArray local_address, jint local_port, jbyteArray peer_address,
    jint peer_port) {
  (void)type;
  uint8_t *config_bytes = NULL;
  uint64_t capacity = 0;
  if (!direct_buffer(env, config_buffer, &config_bytes, &capacity) ||
      capacity < sizeof(quicp_engine_config_t) || path < 0 || path >= 2 ||
      local_port <= 0 || local_port > UINT16_MAX || peer_port <= 0 ||
      peer_port > UINT16_MAX) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  quicp_engine_config_t config;
  memcpy(&config, config_bytes, sizeof(config));
  if ((uint32_t)path >= config.path_count) return QUICP_STATUS_INVALID_ARGUMENT;

  jbyte *elements[2] = {NULL, NULL};
  quicp_bytes_t addresses[2];
  quicp_status_t status = QUICP_STATUS_INVALID_ARGUMENT;
  if (!borrow_bytes(env, local_address, 0, &elements[0], &addresses[0]) ||
      !borrow_bytes(env, peer_address, 0, &elements[1], &addresses[1])) {
    goto done_path;
  }
  if ((addresses[0].length != 4 && addresses[0].length != 16) ||
      addresses[0].length != addresses[1].length) {
    goto done_path;
  }
  quicp_path_config_t *output = &config.paths[path];
  output->local.family = addresses[0].length == 4 ? 4u : 6u;
  output->local.port = (uint16_t)local_port;
  memcpy(output->local.address, addresses[0].data, addresses[0].length);
  output->peer.family = addresses[1].length == 4 ? 4u : 6u;
  output->peer.port = (uint16_t)peer_port;
  memcpy(output->peer.address, addresses[1].data, addresses[1].length);
  memcpy(config_bytes, &config, sizeof(config));
  status = QUICP_STATUS_OK;

done_path:
  if (elements[0] != NULL) {
    (*env)->ReleaseByteArrayElements(env, local_address, elements[0], JNI_ABORT);
  }
  if (elements[1] != NULL) {
    (*env)->ReleaseByteArrayElements(env, peer_address, elements[1], JNI_ABORT);
  }
  return (jint)status;
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeCreate(
    JNIEnv *env, jclass type, jobject config_buffer, jintArray status_output) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (status_output == NULL ||
      (*env)->GetArrayLength(env, status_output) != 1) {
    return 0;
  }
  quicp_status_t status = QUICP_STATUS_INVALID_ARGUMENT;
  if (!direct_buffer(env, config_buffer, &bytes, &capacity) ||
      capacity < sizeof(quicp_engine_config_t) ||
      quicp_abi_version() != QUICP_ABI_VERSION) {
    jint value = (jint)status;
    (*env)->SetIntArrayRegion(env, status_output, 0, 1, &value);
    return 0;
  }
  quicp_engine_config_t config;
  memcpy(&config, bytes, sizeof(config));
  quicp_engine_t *engine = NULL;
  status = quicp_engine_create(&config, &engine);
  jint value = (jint)status;
  (*env)->SetIntArrayRegion(env, status_output, 0, 1, &value);
  return status == QUICP_STATUS_OK ? (jlong)(uintptr_t)engine : 0;
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeCreateTls(
    JNIEnv *env, jclass type, jobject config_buffer, jintArray status_output,
    jbyteArray server_name, jbyteArray ca_certificate, jbyteArray certificate,
    jbyteArray private_key) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  quicp_status_t status = QUICP_STATUS_INVALID_ARGUMENT;
  if (status_output == NULL ||
      (*env)->GetArrayLength(env, status_output) != 1 ||
      !direct_buffer(env, config_buffer, &bytes, &capacity) ||
      capacity < sizeof(quicp_engine_config_t) ||
      quicp_abi_version() != QUICP_ABI_VERSION) {
    jint value = (jint)status;
    if (status_output != NULL &&
        (*env)->GetArrayLength(env, status_output) == 1) {
      (*env)->SetIntArrayRegion(env, status_output, 0, 1, &value);
    }
    return 0;
  }
  jbyte *values[4] = {NULL, NULL, NULL, NULL};
  quicp_tls_config_t tls;
  quicp_engine_t *engine = NULL;
  if (!borrow_bytes(env, server_name, 1, &values[0], &tls.server_name) ||
      !borrow_bytes(env, ca_certificate, 0, &values[1],
                    &tls.ca_certificate) ||
      !borrow_bytes(env, certificate, 0, &values[2], &tls.certificate) ||
      !borrow_bytes(env, private_key, 0, &values[3], &tls.private_key)) {
    goto done;
  }
  quicp_engine_config_t config;
  memcpy(&config, bytes, sizeof(config));
  status = quicp_engine_create_tls(&config, &tls, &engine);

done:
  for (int index = 0; index < 4; ++index) {
    if (values[index] != NULL) {
      jbyteArray input = index == 0   ? server_name
                         : index == 1 ? ca_certificate
                         : index == 2 ? certificate
                                      : private_key;
      (*env)->ReleaseByteArrayElements(env, input, values[index], JNI_ABORT);
    }
  }
  jint value = (jint)status;
  (*env)->SetIntArrayRegion(env, status_output, 0, 1, &value);
  return status == QUICP_STATUS_OK ? (jlong)(uintptr_t)engine : 0;
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeDrive(
    JNIEnv *env, jclass type, jlong handle, jlong elapsed_nanos,
    jint max_tasks) {
  (void)env;
  (void)type;
  if (handle == 0 || elapsed_nanos < 0 || max_tasks <= 0) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  uint32_t processed = 0;
  quicp_status_t status = quicp_engine_drive(
      (quicp_engine_t *)(uintptr_t)handle, (uint64_t)elapsed_nanos,
      (uint32_t)max_tasks, &processed);
  return pack(status, processed);
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeNextTimer(
    JNIEnv *env, jclass type, jlong handle) {
  (void)env;
  (void)type;
  uint32_t present = 0;
  uint64_t deadline = 0;
  if (handle == 0 ||
      quicp_engine_next_timer((quicp_engine_t *)(uintptr_t)handle, &present,
                              &deadline) != QUICP_STATUS_OK ||
      present == 0) {
    return -1;
  }
  return deadline > INT64_MAX ? INT64_MAX : (jlong)deadline;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeConnectionState(
    JNIEnv *env, jclass type, jlong handle) {
  (void)env;
  (void)type;
  return handle == 0
             ? QUICP_STATUS_CLOSED
             : (jint)quicp_engine_connection_state(
                   (quicp_engine_t *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeRecoverySnapshot(
    JNIEnv *env, jclass type, jlong handle, jlongArray output) {
  (void)type;
  if (handle == 0 || output == NULL || (*env)->GetArrayLength(env, output) != 13) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  quicp_recovery_snapshot_t snapshot;
  quicp_status_t status = quicp_engine_recovery_snapshot(
      (quicp_engine_t *)(uintptr_t)handle, &snapshot);
  if (status != QUICP_STATUS_OK) return (jint)status;
  const jlong values[13] = {
      (jlong)snapshot.source_sent,      (jlong)snapshot.source_received,
      (jlong)snapshot.repair_sent,      (jlong)snapshot.recovered,
      (jlong)snapshot.replayed,         (jlong)snapshot.fallback,
      (jlong)snapshot.dropped,          (jlong)snapshot.early_accepted,
      (jlong)snapshot.early_rejected,   (jlong)snapshot.path_lost_packets,
      (jlong)snapshot.max_path_rtt_micros,
      (jlong)snapshot.queued_datagrams, (jlong)snapshot.retained_source_bytes,
  };
  (*env)->SetLongArrayRegion(env, output, 0, 13, values);
  return (*env)->ExceptionCheck(env) ? QUICP_STATUS_FAILED : QUICP_STATUS_OK;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeIngress(
    JNIEnv *env, jclass type, jlong handle, jint path, jobject buffer,
    jint length) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || path < 0 || length <= 0 ||
      !direct_buffer(env, buffer, &bytes, &capacity) ||
      (uint64_t)length > capacity) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  return (jint)quicp_engine_ingress((quicp_engine_t *)(uintptr_t)handle,
                                    (uint32_t)path, bytes,
                                    (uint32_t)length);
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeEgress(
    JNIEnv *env, jclass type, jlong handle, jint path, jobject buffer,
    jint limit) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || path < 0 || limit <= 0 ||
      !direct_buffer(env, buffer, &bytes, &capacity) ||
      (uint64_t)limit > capacity) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  uint32_t length = 0;
  quicp_status_t status = quicp_engine_egress(
      (quicp_engine_t *)(uintptr_t)handle, (uint32_t)path, bytes,
      (uint32_t)limit, &length);
  return pack(status, length);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativePathUnavailable(
    JNIEnv *env, jclass type, jlong handle, jint path) {
  (void)env;
  (void)type;
  if (handle == 0 || path < 0) return QUICP_STATUS_INVALID_ARGUMENT;
  return (jint)quicp_engine_path_unavailable(
      (quicp_engine_t *)(uintptr_t)handle, (uint32_t)path);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeOpenFlow(
    JNIEnv *env, jclass type, jlong handle, jbyteArray host, jint port,
    jlongArray flow_output) {
  (void)type;
  if (handle == 0 || host == NULL || port <= 0 || port > UINT16_MAX ||
      flow_output == NULL || (*env)->GetArrayLength(env, flow_output) != 1) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  jsize length = (*env)->GetArrayLength(env, host);
  if (length <= 0) return QUICP_STATUS_INVALID_ARGUMENT;
  jbyte *bytes = (*env)->GetByteArrayElements(env, host, NULL);
  if (bytes == NULL) return QUICP_STATUS_FAILED;
  quicp_flow_t flow = 0;
  quicp_status_t status = quicp_engine_open_flow(
      (quicp_engine_t *)(uintptr_t)handle, (const uint8_t *)bytes,
      (uint32_t)length, (uint16_t)port, &flow);
  (*env)->ReleaseByteArrayElements(env, host, bytes, JNI_ABORT);
  if (status == QUICP_STATUS_OK) {
    jlong output = (jlong)flow;
    (*env)->SetLongArrayRegion(env, flow_output, 0, 1, &output);
    if ((*env)->ExceptionCheck(env)) return QUICP_STATUS_FAILED;
  }
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeOpenReplaySafeFlow(
    JNIEnv *env, jclass type, jlong handle, jobject token_buffer,
    jint token_length, jlong nonce, jbyteArray host, jint port,
    jobject initial_buffer, jint initial_length, jlongArray flow_output) {
  (void)type;
  uint8_t *token = NULL;
  uint8_t *initial = NULL;
  uint64_t token_capacity = 0;
  uint64_t initial_capacity = 0;
  if (handle == 0 || host == NULL || port <= 0 || port > UINT16_MAX ||
      token_length <= 0 || initial_length <= 0 ||
      !direct_buffer(env, token_buffer, &token, &token_capacity) ||
      !direct_buffer(env, initial_buffer, &initial, &initial_capacity) ||
      (uint64_t)token_length > token_capacity ||
      (uint64_t)initial_length > initial_capacity || flow_output == NULL ||
      (*env)->GetArrayLength(env, flow_output) != 1) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  jsize host_length = (*env)->GetArrayLength(env, host);
  if (host_length <= 0) return QUICP_STATUS_INVALID_ARGUMENT;
  jbyte *host_bytes = (*env)->GetByteArrayElements(env, host, NULL);
  if (host_bytes == NULL) return QUICP_STATUS_FAILED;
  quicp_flow_t flow = 0;
  quicp_status_t status = quicp_engine_open_replay_safe_flow(
      (quicp_engine_t *)(uintptr_t)handle, token, (uint32_t)token_length,
      (uint64_t)nonce, (const uint8_t *)host_bytes, (uint32_t)host_length,
      (uint16_t)port, initial, (uint32_t)initial_length, &flow);
  (*env)->ReleaseByteArrayElements(env, host, host_bytes, JNI_ABORT);
  if (status == QUICP_STATUS_OK) {
    jlong output = (jlong)flow;
    (*env)->SetLongArrayRegion(env, flow_output, 0, 1, &output);
    if ((*env)->ExceptionCheck(env)) return QUICP_STATUS_FAILED;
  }
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativePollFlowRequest(
    JNIEnv *env, jclass type, jlong handle, jboolean replay,
    jobject host_buffer, jobject initial_buffer, jlongArray metadata) {
  (void)type;
  uint8_t *host = NULL;
  uint8_t *initial = NULL;
  uint64_t host_capacity = 0;
  uint64_t initial_capacity = 0;
  if (handle == 0 || metadata == NULL ||
      (*env)->GetArrayLength(env, metadata) != 4 ||
      !direct_buffer(env, host_buffer, &host, &host_capacity) ||
      !direct_buffer(env, initial_buffer, &initial, &initial_capacity) ||
      host_capacity < QUICP_MAX_HOST_BYTES ||
      initial_capacity < QUICP_MAX_EARLY_INITIAL_BYTES) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  uint64_t request = 0;
  uint32_t host_length = 0;
  uint16_t port = 0;
  uint32_t initial_length = 0;
  quicp_status_t status = replay
      ? quicp_engine_poll_replay_safe_flow_request(
            (quicp_engine_t *)(uintptr_t)handle, &request, host,
            (uint32_t)host_capacity, &host_length, &port, initial,
            (uint32_t)initial_capacity, &initial_length)
      : quicp_engine_poll_flow_request(
            (quicp_engine_t *)(uintptr_t)handle, &request, host,
            (uint32_t)host_capacity, &host_length, &port, initial,
            (uint32_t)initial_capacity, &initial_length);
  if (status == QUICP_STATUS_OK) {
    const jlong output[4] = {(jlong)request, (jlong)host_length,
                             (jlong)port, (jlong)initial_length};
    (*env)->SetLongArrayRegion(env, metadata, 0, 4, output);
    if ((*env)->ExceptionCheck(env)) return QUICP_STATUS_FAILED;
  }
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeAcceptPendingFlow(
    JNIEnv *env, jclass type, jlong handle, jlong request,
    jlongArray flow_output) {
  (void)type;
  if (handle == 0 || request <= 0 || flow_output == NULL ||
      (*env)->GetArrayLength(env, flow_output) != 1) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  quicp_flow_t flow = 0;
  quicp_status_t status = quicp_engine_accept_pending_flow(
      (quicp_engine_t *)(uintptr_t)handle, (uint64_t)request, &flow);
  if (status == QUICP_STATUS_OK) {
    jlong output = (jlong)flow;
    (*env)->SetLongArrayRegion(env, flow_output, 0, 1, &output);
    if ((*env)->ExceptionCheck(env)) return QUICP_STATUS_FAILED;
  }
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeRejectPendingFlow(
    JNIEnv *env, jclass type, jlong handle, jlong request) {
  (void)env;
  (void)type;
  return handle == 0 || request <= 0
      ? QUICP_STATUS_INVALID_ARGUMENT
      : (jint)quicp_engine_reject_pending_flow(
            (quicp_engine_t *)(uintptr_t)handle, (uint64_t)request);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeConfigureReplayAdmission(
    JNIEnv *env, jclass type, jlong handle, jobject secret_buffer,
    jint secret_length, jlong epoch, jint max_attempts) {
  (void)type;
  uint8_t *secret = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || secret_length < 32 || max_attempts <= 0 ||
      !direct_buffer(env, secret_buffer, &secret, &capacity) ||
      (uint64_t)secret_length > capacity) {
    return QUICP_STATUS_INVALID_ARGUMENT;
  }
  return (jint)quicp_engine_configure_replay_admission(
      (quicp_engine_t *)(uintptr_t)handle, secret, (uint32_t)secret_length,
      (uint64_t)epoch, (uint32_t)max_attempts);
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeIssueReplayToken(
    JNIEnv *env, jclass type, jlong handle, jlong now_seconds,
    jlong ttl_seconds, jobject output_buffer, jint limit) {
  (void)type;
  uint8_t *output = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || now_seconds < 0 || ttl_seconds <= 0 || limit < 0) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  if (limit > 0 &&
      (!direct_buffer(env, output_buffer, &output, &capacity) ||
       (uint64_t)limit > capacity)) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  uint32_t length = 0;
  quicp_status_t status = quicp_engine_issue_replay_token(
      (quicp_engine_t *)(uintptr_t)handle, (uint64_t)now_seconds,
      (uint64_t)ttl_seconds, output, (uint32_t)limit, &length);
  return pack(status, length);
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeRead(
    JNIEnv *env, jclass type, jlong handle, jlong flow, jobject buffer,
    jint limit) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || flow == 0 || limit <= 0 ||
      !direct_buffer(env, buffer, &bytes, &capacity) ||
      (uint64_t)limit > capacity) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  uint32_t read = 0;
  quicp_status_t status = quicp_flow_read(
      (quicp_engine_t *)(uintptr_t)handle, (quicp_flow_t)flow, bytes,
      (uint32_t)limit, &read);
  return pack(status, read);
}

JNIEXPORT jlong JNICALL Java_io_quicp_QuicpEngine_nativeWrite(
    JNIEnv *env, jclass type, jlong handle, jlong flow, jobject buffer,
    jint length) {
  (void)type;
  uint8_t *bytes = NULL;
  uint64_t capacity = 0;
  if (handle == 0 || flow == 0 || length <= 0 ||
      !direct_buffer(env, buffer, &bytes, &capacity) ||
      (uint64_t)length > capacity) {
    return pack(QUICP_STATUS_INVALID_ARGUMENT, 0);
  }
  uint32_t written = 0;
  quicp_status_t status = quicp_flow_write(
      (quicp_engine_t *)(uintptr_t)handle, (quicp_flow_t)flow, bytes,
      (uint32_t)length, &written);
  return pack(status, written);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeFlush(
    JNIEnv *env, jclass type, jlong handle, jlong flow) {
  (void)env;
  (void)type;
  return handle == 0 || flow == 0
             ? QUICP_STATUS_INVALID_ARGUMENT
             : (jint)quicp_flow_flush((quicp_engine_t *)(uintptr_t)handle,
                                      (quicp_flow_t)flow);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeShutdown(
    JNIEnv *env, jclass type, jlong handle, jlong flow) {
  (void)env;
  (void)type;
  return handle == 0 || flow == 0
             ? QUICP_STATUS_INVALID_ARGUMENT
             : (jint)quicp_flow_shutdown((quicp_engine_t *)(uintptr_t)handle,
                                         (quicp_flow_t)flow);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeCloseFlow(
    JNIEnv *env, jclass type, jlong handle, jlong flow) {
  (void)env;
  (void)type;
  return handle == 0 || flow == 0
             ? QUICP_STATUS_INVALID_ARGUMENT
             : (jint)quicp_flow_close((quicp_engine_t *)(uintptr_t)handle,
                                      (quicp_flow_t)flow);
}

JNIEXPORT jint JNICALL Java_io_quicp_QuicpEngine_nativeClose(
    JNIEnv *env, jclass type, jlong handle) {
  (void)env;
  (void)type;
  quicp_engine_t *engine = (quicp_engine_t *)(uintptr_t)handle;
  return (jint)quicp_engine_close(&engine);
}
