#ifndef __SPDM_COMMON_H__
#define __SPDM_COMMON_H__

#ifndef LIBSPDM_STDINT_ALT
#define LIBSPDM_STDINT_ALT "sbi/sbi_types.h"

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "spdm_device_secret_lib_internal.h"

void *spdm_session_init(void);

#endif
