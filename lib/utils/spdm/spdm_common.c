#include <sbi/sbi_console.h>
#include <sbi/sbi_heap.h>
#include <sbi_utils/spdm/spdm_common.h>

void *spdm_session_init(struct spdm_state *spdm_state)
{
  uint8_t data8;
  uint16_t data16;
  uint32_t data32;
  size_t scratch_buffer_size;
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
    LIBSDPM_SENDER_BUFFER_SIZE,
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
  if (spdm_state->spdm_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = spdm_state->spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_SPDM_VERSION,
                     &parameter,
                     &spdm_version,
                     sizeof(spdm_version));
  }

  if (m_use_secured_message_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = spdm_state->use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context,
                     LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                     &parameter,
                     &spdm_version,
                     sizeof(spdm_version));
  }

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location - LIBSPDM_DATA_LOCATION_LOCAL;

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


}

