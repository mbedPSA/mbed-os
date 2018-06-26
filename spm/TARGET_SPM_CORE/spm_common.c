/* Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cmsis_os2.h"
#include "psa_defs.h"
#include "spm_internal.h"
#include "spm_panic.h"

extern spm_db_t g_spm;

spm_partition_t *get_active_partition(void)
{
    osThreadId_t active_thread_id = osThreadGetId();
    SPM_ASSERT(NULL != active_thread_id);

    for (uint32_t i = 0; i < g_spm.partition_count; ++i) {
        if (g_spm.partitions[i].thread_id == active_thread_id) {
            return &(g_spm.partitions[i]);
        }
    }

    return NULL; // Valid in case of NSPE
}

inline void validate_iovec(
    const void *in_vec,
    const uint32_t in_len,
    const void *out_vec,
    const uint32_t out_len
    )
{
    if (
        !(
            ((in_vec != NULL) || (in_len == 0)) &&
            ((out_vec != NULL) || (out_len == 0)) &&
            (in_len + out_len <= PSA_MAX_IOVEC)
        )
    ) {
        SPM_PANIC("Failed iovec Validation invec=(0X%p) inlen=(%d) outvec=(0X%p) outlen=(%d)\n", in_vec, in_len, out_vec, out_len);
    }
}
