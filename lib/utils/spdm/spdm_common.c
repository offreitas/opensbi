#include <sbi/sbi_console.h>
#include <sbi/sbi_heap.h>
#include <sbi_utils/spdm/spdm_common.h>

void *spdm_session_init(struct spdm_state *spdm_state)
{
  bool res;
  void *data;
  void *data1;
  void *hash;
  void *hash1;
  uint8_t index;
  uint8_t data8;
  uint16_t data16;
  uint32_t data32;
  uint32_t requester_capabilities_flag;
  uint32_t responder_capabilities_flag;
  const uint8_t *root_cert;
  const uint8_t *root_cert1;
  size_t scratch_buffer_size;
  size_t data_size;
  size_t data1_size;
  size_t hash_size;
  size_t hash1_size;
  size_t root_cert_size;
  size_t root_cert1_size;
  spdm_version_number_t spdm_version;
  libspdm_return_t status;
  libspdm_data_parameter_t parameter;

  /*
   * Initializing SPDM context
   * */
  spdm_state->spdm_context = (void *)sbi_malloc(libspdm_get_context_size());
  if (spdm_state->spdm_context == NULL) {
    sbi_printf("[SPDM] Failed tring to allocate SPDM context\n");
    return NULL;
  }

  libspdm_init_context(spdm_state->spdm_context);

  /*
   * Register SPDM send and receive message functions
   * */
  libspdm_register_device_io_func(spdm_state->spdm_context,
                                  spdm_state->spdm_state_ops->send_message,
                                  spdm_state->spdm_state_ops->receive_message);

  /*
   * TODO: add support beyond MCTP
   * */
  if (spdm_state->use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    libspdm_register_transport_layer_func(
      spdm_state->spdm_context,
      LIBSPDM_MAX_MSG_SIZE,
      LIBSPDM_TRANSPORT_HEADER_SIZE,
      LIBSPDM_TRANSPORT_TAIL_SIZE,
      libspdm_transport_mctp_encode_message,
      libspdm_transport_mctp_decode_message
    );
  } else {
    sbi_printf("[SPDM] No SPDM transport layer configured\n");
    sbi_free(spdm_state->spdm_context);
    spdm_state->spdm_context = NULL;
    return NULL;
  }

  /*
   * Register device buffers
   * */
  libspdm_register_device_buffer_func(
    spdm_state->spdm_context,
    LIBSPDM_SENDER_BUFFER_SIZE,
    LIBSPDM_RECEIVER_BUFFER_SIZE,
    spdm_state->spdm_state_ops->acquire_sender_buffer,
    spdm_state->spdm_state_ops->release_sender_buffer,
    spdm_state->spdm_state_ops->acquire_receiver_buffer,
    spdm_state->spdm_state_ops->release_receiver_buffer
  );

  scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_state->spdm_context);
  spdm_state->scratch_buffer = (void *)sbi_malloc(scratch_buffer_size);
  if (spdm_state->scratch_buffer == NULL) {
    sbi_printf("[SPDM] Failed trying to allocate scratch buffer\n");
    sbi_free(spdm_state->spdm_context);
    spdm_state->spdm_context = NULL;
    return NULL;
  }

  libspdm_set_scratch_buffer(spdm_state->spdm_context,
                             spdm_state->scratch_buffer,
                             scratch_buffer_size);

  /*
   * Set connection parameters
   * */
  if (spdm_state->use_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = spdm_state->use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_SPDM_VERSION,
                     &parameter,
                     &spdm_version,
                     sizeof(spdm_version));
  }

  if (spdm_state->use_secured_message_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = spdm_state->use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                     &parameter,
                     &spdm_version,
                     sizeof(spdm_version));
  }

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

  data8 = 0;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                   &parameter,
                   &data8,
                   sizeof(data8));

  data32 = spdm_state->use_requester_capability_flags;
  if (spdm_state->use_slot_id == 0xFF) {
    data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP;
  }
  if (spdm_state->use_capability_flags != 0) {
    data32 = spdm_state->use_capability_flags;
    spdm_state->use_requester_capability_flags = spdm_state->use_capability_flags;
  }
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_CAPABILITY_FLAGS,
                   &parameter,
                   &data32,
                   sizeof(data32));

  data8 = spdm_state->support_measurement_spec;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_MEASUREMENT_SPEC,
                   &parameter,
                   &data8,
                   sizeof(data8));

  data32 = spdm_state->support_asym_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_BASE_ASYM_ALGO,
                   &parameter,
                   &data32,
                   sizeof(data32));

  data32 = spdm_state->support_hash_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_BASE_HASH_ALGO,
                   &parameter,
                   &data32,
                   sizeof(data32));

  data16 = spdm_state->support_dhe_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_DHE_NAME_GROUP,
                   &parameter,
                   &data16,
                   sizeof(data16));

  data16 = spdm_state->support_aead_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                   &parameter,
                   &data16,
                   sizeof(data16));

  data16 = spdm_state->support_req_asym_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                   &parameter,
                   &data16,
                   sizeof(data16));

  data16 = spdm_state->support_key_schedule_algo;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_KEY_SCHEDULE,
                   &parameter,
                   &data16,
                   sizeof(data16));

  data8 = spdm_state->support_other_params_support;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
                   &parameter,
                   &data8,
                   sizeof(data8));

  data8 = spdm_state->support_mel_spec;
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_MEL_SPEC,
                   &parameter,
                   &data8,
                   sizeof(data8));

  /*
   * Initialize SPDM connection
   * TODO: implement special psk case
   * */
  status = libspdm_init_connection(spdm_state->spdm_context,
                                   (spdm_state->exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    sbi_printf("[SPDM] Failed trying to initialize connection: 0x%x\n", (uint32_t)status);
    sbi_free(spdm_state->spdm_context);
    spdm_state->spdm_context = NULL;
    return NULL;
  }

  if (spdm_state->use_version == 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(spdm_version);
    libspdm_get_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_SPDM_VERSION,
                     &parameter,
                     &spdm_version,
                     &data_size);
    spdm_state->use_version = spdm_version >>SPDM_VERSION_NUMBER_SHIFT_BIT;
  }

  /*
   * Get SPDM context configuration
   * */
  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location= LIBSPDM_DATA_LOCATION_LOCAL;
  data_size = sizeof(data32);
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_CAPABILITY_FLAGS,
                   &parameter,
                   &data32,
                   &data_size);
  requester_capabilities_flag = data32;

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
  data_size = sizeof(data32);
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_CAPABILITY_FLAGS,
                   &parameter,
                   &data32,
                   &data_size);
  responder_capabilities_flag = data32;

  /*
   * Change connection and session based on responder/requester capabilities 
   * */
  if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP & responder_capabilities_flag) == 0) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_DIGEST;
    spdm_state->exe_connection &= ~EXE_CONNECTION_CERT;
    spdm_state->exe_session &= ~EXE_CONNECTION_DIGEST;
    spdm_state->exe_session &= ~EXE_CONNECTION_CERT;
  }
  if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP & responder_capabilities_flag) == 0) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_CHAL;
  }
  if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP & responder_capabilities_flag) == 0) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_MEAS;
    spdm_state->exe_session &= ~EXE_SESSION_MEAS;
  }

  if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP & requester_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP & responder_capabilities_flag) == 0)) {
    spdm_state->exe_session &= ~EXE_SESSION_KEY_EX;
  }
  if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP & requester_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP & responder_capabilities_flag) == 0)) {
    spdm_state->exe_session &= ~EXE_SESSION_PSK;
  }
  if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP & requester_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP & responder_capabilities_flag) == 0)) {
    spdm_state->exe_session &= ~EXE_SESSION_KEY_UPDATE;
  }
  if (((SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP & requester_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP & responder_capabilities_flag) == 0)) {
    spdm_state->exe_session &= ~EXE_SESSION_HEARTBEAT;
  }

  if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP & responder_capabilities_flag) == 0) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_SET_CERT;
    spdm_state->exe_session &= ~EXE_SESSION_SET_CERT;
  }
  if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP & responder_capabilities_flag) == 0) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_GET_CSR;
    spdm_state->exe_session &= ~EXE_SESSION_GET_CSR;
  }

  data_size = sizeof(data32);
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_CONNECTION_STATE,
                   &parameter,
                   &data32,
                   &data_size);
  LIBSPDM_ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                   &parameter,
                   &data32,
                   &data_size);
  spdm_state->use_measurement_hash_algo = data32;
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_BASE_ASYM_ALGO,
                   &parameter,
                   &data32,
                   &data_size);
  spdm_state->use_asym_algo = data32;
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_BASE_HASH_ALGO,
                   &parameter,
                   &data32,
                   &data_size);
  spdm_state->use_hash_algo = data32;
  data_size = sizeof(data16);
  libspdm_get_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                   &parameter,
                   &data16,
                   &data_size);
  spdm_state->use_req_asym_algo = data16;

  if ((spdm_state->use_requester_capability_flags &
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0) {
    spdm_state->use_slot_id = 0xFF;
  }
  if (((spdm_state->exe_connection & EXE_CONNECTION_CERT) == 0) &&
       (spdm_state->use_slot_id != 0xFF)) {
    spdm_state->exe_connection &= ~EXE_CONNECTION_CHAL;
    spdm_state->exe_connection &= ~EXE_CONNECTION_MEAS;
    spdm_state->exe_session &= ~EXE_SESSION_KEY_EX;
    spdm_state->exe_session &= ~EXE_SESSION_MEAS;
  }
  if (spdm_state->use_slot_id == 0xFF) {
    res = libspdm_read_responder_public_key(spdm_state->use_asym_algo, &data, &data_size);
    if (res) {
      libspdm_zero_mem(&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data(spdm_state->spdm_context,
                       LIBSPDM_DATA_PEER_PUBLIC_KEY,
                       &parameter,
                       data,
                       data_size);
      /* Do not free it */
    } else {
      sbi_printf("[SPDM] Failed at read_responder_public_key\n");
      sbi_free(spdm_state->spdm_context);
      spdm_state->spdm_context = NULL;
      return NULL;
    }
    res = libspdm_read_requester_public_key(spdm_state->use_req_asym_algo, &data, &data_size);
    if (res) {
      libspdm_zero_mem(&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data(spdm_state->spdm_context,
                       LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                       &parameter,
                       data,
                       data_size);
      /* Do not free it */
    } else {
      sbi_printf("[SPDM] Failed at read_requester_public_key\n");
      sbi_free(spdm_state->spdm_context);
      spdm_state->spdm_context = NULL;
      return NULL;
    }
  } else {
    res = libspdm_read_responder_root_public_certificate(spdm_state->use_hash_algo,
                                                         spdm_state->use_asym_algo,
                                                         &data, &data_size,
                                                         &hash, &hash_size);
    if (res) {
      libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                            data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                            &root_cert, &root_cert_size);
      libspdm_zero_mem(&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data(spdm_state->spdm_context,
                      LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                      &parameter,
                      (void *)root_cert,
                      root_cert_size);
      /* Do not free it */
    } else {
      sbi_printf("[SPDM] Failed at read_responder_root_public_certificate\n");
      sbi_free(spdm_state->spdm_context);
      spdm_state->spdm_context = NULL;
      return NULL;
    }

    res = libspdm_read_responder_root_public_certificate_slot(1,
                                                              spdm_state->use_hash_algo,
                                                              spdm_state->use_asym_algo,
                                                              &data1, &data1_size,
                                                              &hash1, &hash1_size);
    if (res) {
      libspdm_x509_get_cert_from_cert_chain((uint8_t *)data1 + sizeof(spdm_cert_chain_t) + hash1_size,
                                            data1_size - sizeof(spdm_cert_chain_t) - hash1_size, 0,
                                            &root_cert1, &root_cert1_size);
      libspdm_zero_mem(&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data(spdm_state->spdm_context,
                       LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                       &parameter,
                       (void *)root_cert1,
                       root_cert1_size);
      /* Do not free it */
    } else {
      sbi_printf("[SPDM] Failed at read_responder_root_public_certificate_slot\n");
      sbi_free(spdm_state->spdm_context);
      spdm_state->spdm_context = NULL;
      return NULL;
    }
  }

  if (spdm_state->use_req_asym_algo != 0) {
    res = libspdm_read_requester_public_certificate_chain(spdm_state->use_hash_algo,
                                                          spdm_state->use_req_asym_algo,
                                                          &data, &data_size, NULL, NULL);
    if (res) {
      libspdm_zero_mem(&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      for (index = 0; index < spdm_state->use_slot_count; index++) {
        parameter.additional_data[0] = index;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                         &parameter,
                         data,
                         data_size);
        data8 = (uint8_t)(0xB0 + index);
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_LOCAL_KEY_PAIR_ID,
                         &parameter,
                         &data8,
                         sizeof(data8));
        data8 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_LOCAL_CERT_INFO,
                         &parameter,
                         &data8, sizeof(data8));
        data16 = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
                 SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
                 SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
                 SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK,
                         &parameter,
                         &data16,
                         sizeof(data16));
        /* Do not free it */
      }
    } else {
      sbi_printf("[SPDM] Failed at read_requester_public_certificate_chain\n");
      sbi_free(spdm_state->spdm_context);
      spdm_state->spdm_context = NULL;
      return NULL;
    }
  }

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  data8 = 0;
  for (index = 0; index < spdm_state->use_slot_count; index++) {
    data8 |= (1 << index);
  }
  libspdm_set_data(spdm_state->spdm_context,
                   LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                   &parameter,
                   &data8,
                   sizeof(data8));

  return NULL;
}

