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
#if !ENABLE_SPM
    #error [NOT_SUPPORTED] SPM is not supported on this platform
#endif

#include <stdlib.h>
#include "cmsis_os2.h"
#include "mbed_rtos_storage.h"
#include "mbed_error.h"


mbed_rtos_storage_mem_pool_t g_storage = {0};
int g_data[5] = {0};
const osMemoryPoolAttr_t g_attributes = {
    .name = "Dummy",
    .attr_bits = 0,
    .cb_mem = &g_storage,
    .cb_size = sizeof(g_storage),
    .mp_mem = g_data,
    .mp_size = sizeof(g_data)
};

int main(int argc, char **argv) {
    osMemoryPoolId_t pool_id = osMemoryPoolNew(
        5,
        sizeof(int),
        &g_attributes
        );
    if (NULL == pool_id) {
        error("%s - Failed to create channel memory pool!\n", __func__);
    }

    void *data = osMemoryPoolAlloc(pool_id, osWaitForever);
    void *data2 = malloc(sizeof(int));

    return 0;
}
