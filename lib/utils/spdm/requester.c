#include <sbi/sbi_console.h>
#include <sbi_utils/spdm/common.h>

void *spdm_session_init(void *m_spdm_context)
{
  void *spdm_context;
  uint8_t data8;
  uint16_t data16;
  uint32_t data32;
  spdm_version_number_t spdm_version;
  libspdm_return_t status;
  libspdm_data_parameter_t parameter;

  sbi_printf("SPDM context size 0x%0x\n", (uint32_t)libspdm_get_context_size());

  m_spdm_context = (void *)malloc()
}

