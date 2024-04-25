#ifndef __SPDM_COMMON_H__
#define __SPDM_COMMON_H__

#ifndef LIBSPDM_STDINT_ALT
#define LIBSPDM_STDINT_ALT "sbi/sbi_types.h"

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "spdm_device_secret_lib_internal.h"

#define LIBSPDM_MAX_MSG_SIZE 0x1200
#define LIBSPDM_TRANSPORT_HEADER_SIZE 64 
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
  (LIBSPDM_TRANSPORT_HEADER_SIZE + lIBSPDM_TRANSPORT_TAIL_SIZE)

#define LIBSPDM_SENDER_BUFFER_SIZE (0x1000 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1000 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)

#define SOCKET_TRANSPORT_TYPE_NONE 0x00
#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02
#define SOCKET_TRANSPORT_TYPE_TCP 0x03

struct spdm_ops {
  // Message exchange functions
  libspdm_return_t (*send_message) (void *spdm_context,
                                    size_t request_size,
                                    const void *request,
                                    uint64_t timeout);
  libspdm_return_t (*receive_message) (void *spdm_context,
                                       size_t response_size,
                                       void **response,
                                       uint64_t timeout);

  // Buffers' functions
  libspdm_return_t (*acquire_sender_buffer) (void *context,
                                             void **msg_but_ptr);
  void (*release_sender_buffer) (void *context, const void *msg_buf_ptr);
  libspdm_return_t (*acquire_receiver_buffer) (void *context,
                                               void **msg_but_ptr);
  void (*release_receiver_buffer) (void *context, const void *msg_buf_ptr);
}

struct spdm_state {
  void *spdm_context;
  
  void *scratch_buffer;

  uint8_t use_version;
  uint8_t use_secured_message_version;
  uint8_t use_slot_id;
  uint32_t use_transport_layer;

  uint8_t support_measurement_spec;
  uint8_t support_other_params_support;
  uint8_t support_mel_spec;
  uint16_t support_dhe_algo;
  uint16_t support_aead_algo;
  uint16_t support_req_asym_algo;
  uint16_t support_key_schedule_algo;
  uint32_t use_requester_capability_flags;
  uint32_t use_capability_flags;
  uint32_t support_asym_algo;
  uint32_t support_hash_algo;

  uint32_t exe_connection;

  struct spdm_ops *spdm_state_ops;
}

void *spdm_session_init(struct spdm_state *spdm_state);

#endif
